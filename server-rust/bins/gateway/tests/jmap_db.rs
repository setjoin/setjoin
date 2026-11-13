//! DB-backed black-box proofs for native JMAP (#215/#216/#315): the real
//! gateway with the route installed, a fake Go upstream that records what
//! reaches it, a real schema, and tokens signed by a test ES256 key served
//! through the JWKS client.
//!
//! Gate and fixtures are the conformance harness's: owner DSN
//! `TEST_DB_DSN`/`DB_DSN`, the route's pool on `DB_APP_DSN` (`setjoin_app`)
//! when set; no DSN → `CONFORMANCE-SKIP` line, `REQUIRE_DB=1` → FAIL.
//! The cases share the `feature_toggles` rows they flip, so they run one at a
//! time and restore every row they touched.
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;
use hyper::Request;
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use setjoin_conformance::fixture::{self, Account};
use setjoin_conformance::harness::Db;
use setjoin_gateway::jmap::jwks::{jwk, Jwks};
use setjoin_gateway::jmap::limit::{EdgeLimit, Limiter};
use setjoin_gateway::jmap::{JmapCommands, JmapRoute};
use setjoin_gateway::RouteTable;
use setjoin_pg::ScopedExecutor;
use tokio::sync::Mutex;
use tokio_postgres::types::Type;
use tokio_postgres::Client;

use common::golden::{self, retarget, retarget_item, Value::*};
use common::{full, BoxError};

/// The gateway's verifying key for a RustCrypto test signer (production
/// verifies ES256 with ring).
fn public(key: &SigningKey) -> setjoin_gateway::jmap::token::VerifyingKey {
    setjoin_gateway::jmap::token::VerifyingKey::from_sec1(
        key.verifying_key().to_sec1_point(false).as_bytes(),
    )
    .unwrap()
}

static SERIAL: Mutex<()> = Mutex::const_new(());
const KID: &str = "test-es256-1";
const TOGGLES: [&str; 7] = [
    "feature.rust_mark_read",
    "feature.rust_inbox_list",
    "feature.cae_runtime",
    "feature.device_trust_enforcement",
    "feature.conditional_access",
    "feature.device_lockdown",
    "rbac.jit",
];

struct Env {
    owner: Client,
    gateway: std::net::SocketAddr,
    exec: ScopedExecutor,
    upstream_hits: Arc<AtomicUsize>,
    key: SigningKey,
    a: Account,
    b: Account,
    saved: Vec<(String, Option<bool>)>,
    guests: Mutex<Vec<i64>>,
    sessions: Option<Arc<setjoin_gateway::workers::SessionDenylist>>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn env(db: &Db) -> Env {
    env_with_denylist(db, None).await
}

async fn env_with_denylist(
    db: &Db,
    denylist: Option<Arc<setjoin_gateway::workers::SessionDenylist>>,
) -> Env {
    let owner = db.connect().await.expect("owner connection");
    let mut saved = Vec::new();
    for key in TOGGLES {
        let rows = owner
            .query_typed(
                "SELECT enabled FROM feature_toggles WHERE key = $1",
                &[(&key, Type::TEXT)],
            )
            .await
            .unwrap();
        saved.push((key.to_owned(), rows.first().map(|r| r.get(0))));
        // Every case starts from all saved toggles OFF (a shared DB may carry e.g. the
        // e2e seed's cae_runtime ON); close() restores the saved values.
        owner
            .query_typed(
                "INSERT INTO feature_toggles (key, enabled) VALUES ($1, FALSE) \
                 ON CONFLICT (key) DO UPDATE SET enabled = FALSE",
                &[(&key, Type::TEXT)],
            )
            .await
            .unwrap();
    }
    let a = fixture::account(&owner, "gw-a").await.expect("fixture a");
    let b = fixture::account(&owner, "gw-b").await.expect("fixture b");

    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let upstream = common::fake_upstream(move |_req| {
        counter.fetch_add(1, Ordering::SeqCst);
        async {
            hyper::Response::builder()
                .status(299)
                .body(full("from go"))
                .unwrap()
        }
    })
    .await;

    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let doc = json!({ "keys": [jwk(KID, &public(&key))] })
        .to_string()
        .into_bytes();
    let jwks = Arc::new(Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    })));
    let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).expect("pool");
    let component_only = denylist.is_some();
    let route = JmapRoute(Arc::new(JmapCommands {
        services: None,
        worker: None,
        denylist:denylist.clone(),
        exec: exec.clone(),
        keys: jwks.clone(),
        issuer: "mailserver".into(),
    }));
    let mut routes = RouteTable::proxy_all().with(route);
    if component_only {
        routes = routes.with_admission(
            ScopedExecutor::from_dsn(&db.dsn, 2).expect("worker pool"),
            jwks.clone(), "mailserver".into(), denylist,
        );
    }
    // An explicitly injected cold cache tests the adapter seam alone. All other
    // cases use production's central runtime chain, including flag-ON cases.
    let sessions = if component_only { None } else {
        let worker_db = setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap();
        let runtime = setjoin_gateway::runtime_access::RuntimeAccess::new(exec.clone(), jwks, "mailserver".into())
            .with_workers(ScopedExecutor::from_dsn(&db.dsn, 2).unwrap(), worker_db)
            .with_direct(db.direct.clone());
        let sessions = runtime.session_cache();
        routes = routes.with_runtime(runtime);
        sessions
    };
    let gateway = common::gateway_limited(
        upstream,
        routes,
        EdgeLimit::for_front_door(Limiter::new(600, 60)),
    )
    .await;
    Env {
        owner,
        gateway,
        exec,
        upstream_hits: hits,
        key,
        a,
        b,
        saved,
        guests: Mutex::new(Vec::new()),
        sessions,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_cache_gates_the_actual_jmap_http_route() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("worker_cache_gates_the_actual_jmap_http_route") else {
        return Ok(());
    };
    let _serial = SERIAL.lock().await;
    let worker = Arc::new(setjoin_gateway::workers::SessionDenylist::new(
        setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap(),
    ));
    let e = env_with_denylist(&db, Some(worker.clone())).await;
    let result = std::panic::AssertUnwindSafe(async {
        e.toggle("feature.rust_mark_read", true).await;
        let token = e.token(e.a.user, |_| {});
        let body = seen_body(e.a.mailbox, e.a.inbox_only, SEEN);
        let (status, _, hit) = e.post(&token, &body).await;
        assert_eq!((status, hit), (200, false), "Go permits a cold cache when CAE is off");
        worker.refresh_once().await.unwrap();
        let (status, _, hit) = e.post(&token, &body).await;
        assert_eq!((status, hit), (200, false), "loaded cache permits a live session");
        let jti = format!("jti-{}", e.a.user);
        e.owner.query_typed(
            "INSERT INTO session_revocations(user_id,scope,jti,not_before,reason,expires_at) VALUES ($1,'jti',$2,now(),'worker cache test',now()+interval '1 hour')",
            &[(&e.a.user, Type::INT8), (&jti, Type::TEXT)],
        ).await.unwrap();
        worker.refresh_once().await.unwrap();
        e.owner.query_typed("DELETE FROM session_revocations WHERE user_id=$1 AND jti=$2", &[(&e.a.user, Type::INT8), (&jti, Type::TEXT)]).await.unwrap();
        let (status, _, hit) = e.post(&token, &body).await;
        assert_eq!((status, hit), (401, false), "last known revocation is a native denial");
    }).catch_unwind_compat().await;
    e.close().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    Ok(())
}

impl Env {
    async fn toggle(&self, key: &str, enabled: bool) {
        self.owner
            .query_typed(
                "INSERT INTO feature_toggles (key, enabled) VALUES ($1, $2) \
                 ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled",
                &[(&key, Type::TEXT), (&enabled, Type::BOOL)],
            )
            .await
            .unwrap();
    }

    fn token(&self, user: i64, patch: impl FnOnce(&mut Value)) -> String {
        let mut claims = json!({
            "uid": user, "email": "x@test", "typ": "access", "jti": format!("jti-{user}"),
            "fam": format!("fam-{user}"), "iss": "mailserver", "aud": ["mailserver-gateway"],
            "iat": now() - 10, "exp": now() + 600,
        });
        patch(&mut claims);
        sign(
            &self.key,
            &json!({"alg": "ES256", "kid": KID, "typ": "JWT"}),
            &claims,
        )
    }

    /// POST /jmap through the gateway; (status, body, upstream hit?).
    async fn post(&self, token: &str, body: &str) -> (u16, String, bool) {
        let before = self.upstream_hits.load(Ordering::SeqCst);
        let req = Request::post("/jmap")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(full(body.to_owned()))
            .unwrap();
        let resp = common::send(self.gateway, req).await;
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let hit = self.upstream_hits.load(Ordering::SeqCst) > before;
        (status, String::from_utf8(bytes.to_vec()).unwrap(), hit)
    }

    async fn is_read(&self, message: i64) -> bool {
        self.owner
            .query_typed(
                "SELECT is_read FROM messages WHERE id = $1",
                &[(&message, Type::INT8)],
            )
            .await
            .unwrap()[0]
            .get(0)
    }

    async fn active_guest(&self) -> i64 {
        let email = format!("gofree-t5-guest-{}@example.test", self.a.user);
        let user: i64 = self.owner.query_typed(
            "INSERT INTO users (username, domain_id, email, display_name, password_hash) \
             VALUES ($1, (SELECT id FROM domains WHERE name='guest.invalid'), $1, 'T5 guest', 'x') RETURNING id",
            &[(&email, Type::TEXT)],
        ).await.unwrap()[0].get(0);
        self.guests.lock().await.push(user);
        self.owner.query_typed(
            "INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, status) \
             VALUES ($1, $2, 'inviter@example.test', $3, 'active')",
            &[(&user, Type::INT8), (&email, Type::TEXT), (&self.a.domain, Type::INT8)],
        ).await.unwrap();
        user
    }

    async fn session_state(&self, user: i64) -> String {
        let r = &self
            .owner
            .query_typed(
                "SELECT m.jmap_email_state, m.jmap_mailbox_state, m.jmap_thread_state, m.jmap_tag_state, \
                        floor(extract(epoch FROM u.updated_at))::int8 \
                   FROM mailboxes m JOIN users u ON u.id = m.user_id \
                  WHERE m.user_id = $1 AND m.is_primary",
                &[(&user, Type::INT8)],
            )
            .await
            .unwrap()[0];
        let g = |i: usize| r.get::<_, i64>(i);
        format!("{}-{}-{}-{}-0-0-0-{}", g(0), g(1), g(2), g(3), g(4))
    }

    async fn close(self) {
        for (key, value) in &self.saved {
            match value {
                Some(v) => self.toggle(key, *v).await,
                None => {
                    self.owner
                        .query_typed(
                            "DELETE FROM feature_toggles WHERE key = $1",
                            &[(key, Type::TEXT)],
                        )
                        .await
                        .unwrap();
                }
            }
        }
        for user in self.guests.lock().await.iter() {
            self.owner
                .query_typed("DELETE FROM users WHERE id=$1", &[(user, Type::INT8)])
                .await
                .unwrap();
        }
        fixture::remove(&self.owner, &self.a).await.unwrap();
        fixture::remove(&self.owner, &self.b).await.unwrap();
    }
}

fn sign(key: &SigningKey, header: &Value, claims: &Value) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Signer;
    let h = URL_SAFE_NO_PAD.encode(header.to_string());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string());
    let sig: p256::ecdsa::Signature = key.sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn seen_body(account: i64, message: i64, patch: &str) -> String {
    format!(
        r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{{"accountId":"{account}","create":null,"update":{{"{message}":{patch}}},"destroy":null}},"0"]]}}"#
    )
}

const SEEN: &str = r#"{"keywords":{"$seen":true}}"#;

macro_rules! db_case {
    ($name:ident, |$e:ident| $body:block) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let Some(db) = Db::for_case(stringify!($name)) else {
                return Ok(());
            };
            let _serial = SERIAL.lock().await;
            let $e = env(&db).await;
            let result = std::panic::AssertUnwindSafe(async { $body })
                .catch_unwind_compat()
                .await;
            $e.close().await;
            if let Err(p) = result {
                std::panic::resume_unwind(p);
            }
            Ok(())
        }
    };
}

trait CatchUnwindCompat: std::future::Future + Sized {
    fn catch_unwind_compat(self) -> CatchUnwind<Self> {
        CatchUnwind(Box::pin(self))
    }
}
impl<F: std::future::Future> CatchUnwindCompat for std::panic::AssertUnwindSafe<F> {}
struct CatchUnwind<F: std::future::Future>(std::pin::Pin<Box<F>>);
impl<F: std::future::Future> std::future::Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let fut = self.0.as_mut();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.poll(cx))) {
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Ok(std::task::Poll::Ready(v)) => std::task::Poll::Ready(Ok(v)),
            Err(p) => std::task::Poll::Ready(Err(p)),
        }
    }
}

// A second, test-only family exercises the shared authorization boundary
// through the real front door without using the JMAP adapter's internals.
struct AuthContextProbe {
    exec: ScopedExecutor,
    keys: Arc<Jwks>,
}

impl setjoin_gateway::Intercept for AuthContextProbe {
    fn matches(&self, req: &Request<setjoin_gateway::Body>) -> bool {
        req.uri().path() == "/jmap"
    }

    fn handle(
        &self,
        req: Request<setjoin_gateway::Body>,
        ctx: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<hyper::Response<setjoin_gateway::Body>> {
        let exec = self.exec.clone();
        let keys = self.keys.clone();
        Box::pin(async move {
            let Some(auth) = setjoin_authz::authorize(
                &exec,
                keys.as_ref(),
                "mailserver",
                req.headers(),
                ctx.identity.proto,
                "feature.rust_mark_read",
            )
            .await
            else {
                return ctx.upstream.forward(req, &ctx.identity).await;
            };
            let identity = auth.context();
            let body = json!({
                "user": identity.user_id(),
                "mailbox": identity.mailbox_id(),
                "domain_scope": identity.signed_domain_scope(),
                "admin": identity.signed_admin(),
                "permissions": identity.signed_permissions(),
                "roles": identity.roles(),
            })
            .to_string();
            hyper::Response::new(full(body))
        })
    }
}

db_case!(
    shared_auth_context_uses_verified_claims_and_primary_mailbox,
    |e| {
        e.toggle("feature.rust_mark_read", true).await;
        let doc = json!({ "keys": [jwk(KID, &public(&e.key))] })
            .to_string()
            .into_bytes();
        let keys = Arc::new(Jwks::with_fetch(Box::new(move || {
            let doc = doc.clone();
            Box::pin(async move { Ok(doc) })
        })));
        let upstream =
            common::fake_upstream(|_| async { hyper::Response::new(full("deferred")) }).await;
        let gateway = common::gateway(
            upstream,
            "",
            RouteTable::proxy_all().with(AuthContextProbe {
                exec: e.exec.clone(),
                keys,
            }),
        )
        .await;
        let token = e.token(e.a.user, |claims| {
            claims["domain"] = json!(12345);
            claims["admin"] = json!(true);
            claims["perms"] = json!(["mail.read", "mail.write"]);
        });
        let req = Request::post("/jmap")
            .header("host", "mail.test")
            .header("authorization", format!("Bearer {token}"))
            .body(full(
                json!({ "user": e.b.user, "mailbox": e.b.mailbox, "domain_scope": 999 })
                    .to_string(),
            ))
            .unwrap();
        let resp = common::send(gateway, req).await;
        assert_eq!(resp.status(), 200);
        let body: Value = serde_json::from_slice(&common::body_bytes(resp).await).unwrap();
        assert_eq!(
            body,
            json!({
                "user": e.a.user,
                "mailbox": e.a.mailbox,
                "domain_scope": 12345,
                "admin": true,
                "permissions": ["mail.read", "mail.write"],
                "roles": [],
            })
        );
    }
);

db_case!(shared_auth_context_tracks_live_role_revocation, |e| {
    e.toggle("feature.rust_mark_read", true).await;
    // Role IDs are Go's governed role-group IDs, never JWT role names.
    e.owner
        .query_typed(
            "INSERT INTO admin_role_assignments(user_id, role_group_id) VALUES ($1, 2), ($2, 4)",
            &[(&e.a.user, Type::INT8), (&e.b.user, Type::INT8)],
        )
        .await
        .unwrap();
    let doc = json!({ "keys": [jwk(KID, &public(&e.key))] })
        .to_string()
        .into_bytes();
    let keys = Arc::new(Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    })));
    let upstream = common::fake_upstream(|_| async {
        hyper::Response::builder()
            .status(299)
            .body(full("deferred"))
            .unwrap()
    })
    .await;
    let gateway = common::gateway(
        upstream,
        "",
        RouteTable::proxy_all().with(AuthContextProbe {
            exec: e.exec.clone(),
            keys,
        }),
    )
    .await;
    let token = e.token(e.a.user, |claims| {
        claims["admin"] = json!(true);
        claims["roles"] = json!([4]);
    });
    for expected in [json!([2]), json!([])] {
        let req = Request::post("/jmap")
            .header("host", "mail.test")
            .header("authorization", format!("Bearer {token}"))
            .header("x-user-id", e.b.user.to_string())
            .body(full(
                json!({"user": e.b.user, "mailbox": e.b.mailbox, "roles": [4]}).to_string(),
            ))
            .unwrap();
        let resp = common::send(gateway, req).await;
        assert_eq!(resp.status(), 200);
        let body: Value = serde_json::from_slice(&common::body_bytes(resp).await).unwrap();
        assert_eq!(body["user"], e.a.user);
        assert_eq!(body["mailbox"], e.a.mailbox);
        assert_eq!(body["roles"], expected);
        // Reusing the token must not retain a revoked assignment.
        e.owner
            .query_typed(
                "DELETE FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 2",
                &[(&e.a.user, Type::INT8)],
            )
            .await
            .unwrap();
    }
});

db_case!(live_roles_honor_expiry_and_jit_activation, |e| {
    e.toggle("feature.rust_mark_read", true).await;
    e.toggle("rbac.jit", true).await;
    e.owner
        .query_typed(
            "INSERT INTO admin_role_assignments(user_id, role_group_id, expires_at) \
         VALUES ($1, 2, now() - interval '1 hour'), ($2, 4, NULL)",
            &[(&e.a.user, Type::INT8), (&e.b.user, Type::INT8)],
        )
        .await
        .unwrap();
    let doc = json!({ "keys": [jwk(KID, &public(&e.key))] })
        .to_string()
        .into_bytes();
    let keys = Arc::new(Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    })));
    let upstream = common::fake_upstream(|_| async {
        hyper::Response::builder()
            .status(299)
            .body(full("deferred"))
            .unwrap()
    })
    .await;
    let gateway = common::gateway(
        upstream,
        "",
        RouteTable::proxy_all().with(AuthContextProbe {
            exec: e.exec.clone(),
            keys,
        }),
    )
    .await;
    let token = e.token(e.a.user, |c| c["admin"] = json!(true));
    for (expected, transition) in [
        (json!([]), "expires_at = NULL, eligible = TRUE"),
        (json!([]), "activated_until = now() + interval '1 hour'"),
        (json!([2]), "activated_until = now() - interval '1 hour'"),
        (json!([]), "eligible = FALSE"),
    ] {
        let req = Request::post("/jmap")
            .header("host", "mail.test")
            .header("authorization", format!("Bearer {token}"))
            .body(full(""))
            .unwrap();
        let resp = common::send(gateway, req).await;
        assert_eq!(resp.status(), 200);
        let body: Value = serde_json::from_slice(&common::body_bytes(resp).await).unwrap();
        assert_eq!(body["roles"], expected, "before {transition}");
        // SQL fragments are fixed fixture transitions, never request input.
        e.owner.query_typed(
            &format!("UPDATE admin_role_assignments SET {transition} WHERE user_id = $1 AND role_group_id = 2"),
            &[(&e.a.user, Type::INT8)],
        ).await.unwrap();
    }
    // Go skips admin permission resolution for a signed non-admin token,
    // even if an assignment was granted after that token was issued.
    let non_admin = e.token(e.a.user, |_| {});
    let req = Request::post("/jmap")
        .header("host", "mail.test")
        .header("authorization", format!("Bearer {non_admin}"))
        .body(full(""))
        .unwrap();
    let resp = common::send(gateway, req).await;
    assert_eq!(resp.status(), 200);
    let body: Value = serde_json::from_slice(&common::body_bytes(resp).await).unwrap();
    assert_eq!(body["roles"], json!([]));
});

db_case!(mark_read_matches_go_with_pilot_flag_off_and_on, |e| {
    let token = e.token(e.a.user, |_| {});
    for (enabled, msg) in [(false, e.a.inbox_only), (true, e.a.two_labels)] {
        e.toggle("feature.rust_mark_read", enabled).await;
        let old = fixture::snapshot(&e.owner, e.a.mailbox)
            .await
            .unwrap()
            .email_state;
        let expected = e.go_set_updated_bytes(msg, old, old + 1).await;
        let audit = e.audit_rows(e.a.mailbox).await;
        let (status, body, hit) = e.post(&token, &seen_body(e.a.mailbox, msg, SEEN)).await;
        assert_eq!((status, hit), (200, false), "mark-read flag={enabled}");
        assert_eq!(body, expected, "mark-read flag={enabled}");
        assert!(e.is_read(msg).await);
        assert_eq!(e.audit_rows(e.a.mailbox).await, audit + 1);
    }
});

db_case!(flag_on_serves_exactly_the_seen_case_in_go_shape, |e| {
    e.toggle("feature.rust_mark_read", true).await;
    let token = e.token(e.a.user, |_| {});
    let before = fixture::snapshot(&e.owner, e.a.mailbox).await.unwrap();
    let state = e.session_state(e.a.user).await;
    let (status, body, hit) = e
        .post(&token, &seen_body(e.a.mailbox, e.a.two_labels, SEEN))
        .await;
    assert!(!hit, "served by Rust, not Go");
    assert_eq!(status, 200);
    let (old, new) = (before.email_state, before.email_state + 1);
    let (mb, msg) = (e.a.mailbox, e.a.two_labels);
    // Go's own bytes for this answer (captured golden), re-targeted at
    // this fixture's values.
    let msg_s = msg.to_string();
    assert_eq!(
        body,
        retarget(
            golden::SET_UPDATED,
            &[
                ("sessionState", Str(&state)),
                ("accountId", Str(&mb.to_string())),
                ("newState", Str(&new.to_string())),
                ("oldState", Str(&old.to_string())),
                ("updated", Array(&msg_s)),
            ]
        )
    );
    let after = fixture::snapshot(&e.owner, e.a.mailbox).await.unwrap();
    assert!(after.is_read[&msg]);
    assert_eq!(after.unread(e.a.inbox), before.unread(e.a.inbox) - 1);
    assert_eq!(after.unread(e.a.label), before.unread(e.a.label) - 1);
    assert_eq!(after.email_state, new);

    // Repeat: a no-op read answers like the reducer, old = new state.
    let (_, body, hit) = e.post(&token, &seen_body(mb, msg, SEEN)).await;
    assert!(!hit);
    assert!(
        body.contains(&format!(
            "\"newState\":\"{new}\",\"notUpdated\":{{}},\"oldState\":\"{new}\""
        )),
        "{body}"
    );
});

db_case!(
    general_email_patches_and_plain_get_are_native_with_either_pilot_flag,
    |e| {
        let token = e.token(e.a.user, |_| {});
        let mb = e.a.mailbox;
        for (enabled, msg) in [(false, e.a.inbox_only), (true, e.a.two_labels)] {
            e.toggle("feature.rust_mark_read", enabled).await;
            let move_label = format!(
                r#"{{"keywords":{{"$seen":true}},"mailboxIds":{{"{}":true}}}}"#,
                e.a.label
            );
            for (patch, bump) in [
                (r#"{"keywords":{"$seen":true,"$flagged":true}}"#, 1),
                // Frozen Go accepts a patch path but ignores it: preserve its no-op.
                (r#"{"keywords/$seen":false}"#, 0),
                (move_label.as_str(), 1),
            ] {
                let old = fixture::snapshot(&e.owner, mb).await.unwrap().email_state;
                let expected = e.go_set_updated_bytes(msg, old, old + bump).await;
                let (status, body, hit) = e.post(&token, &seen_body(mb, msg, patch)).await;
                assert_eq!((status, hit), (200, false), "flag={enabled}: {patch}");
                assert_eq!(body, expected, "flag={enabled}: {patch}");
                assert!(e.is_read(msg).await);
            }
            let get = format!(
                r#"{{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/get",{{"accountId":"{mb}","ids":["{}","{}"]}},"0"]]}}"#,
                e.a.inbox_only, e.a.two_labels
            );
            let (status, body, hit) = e.post(&token, &get).await;
            assert_eq!((status, hit), (200, false), "plain get flag={enabled}");
            let body: Value = serde_json::from_str(&body).unwrap();
            let response = &body["methodResponses"][0];
            assert_eq!(response[0], "Email/get");
            // Frozen Go records an empty notFound slice as null.
            assert_eq!(response[1]["notFound"], Value::Null);
            let mut ids: Vec<_> = response[1]["list"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["id"].as_str().unwrap().to_owned())
                .collect();
            ids.sort();
            let mut expected = vec![e.a.inbox_only.to_string(), e.a.two_labels.to_string()];
            expected.sort();
            assert_eq!(ids, expected);
        }
    }
);

db_case!(tokens_go_rejects_are_left_to_go, |e| {
    e.toggle("feature.rust_mark_read", true).await;
    let (mb, msg, user) = (e.a.mailbox, e.a.inbox_only, e.a.user);
    let body = seen_body(mb, msg, SEEN);
    let expired = e.token(user, |c| c["exp"] = json!(now() - 1));
    let refresh = e.token(user, |c| c["typ"] = json!("refresh"));
    let wrong_aud = e.token(user, |c| c["aud"] = json!("someone-else"));
    let foreign_key = sign(
        &SigningKey::from_slice(&[0x22; 32]).unwrap(),
        &json!({"alg": "ES256", "kid": KID}),
        &json!({"uid": user, "typ": "access", "iss": "mailserver", "aud": "mailserver-gateway", "iat": now(), "exp": now() + 60}),
    );
    for (name, token) in [
        ("expired", expired),
        ("refresh", refresh),
        ("audience", wrong_aud),
        ("foreign key", foreign_key),
        ("garbage", "a.b.c".into()),
    ] {
        let (status, _, hit) = e.post(&token, &body).await;
        assert_eq!((status, hit), (299, true), "{name}");
    }

    // A revoked session (admin "sign out everywhere": scope=all watermark).
    let token = e.token(user, |_| {});
    e.owner
        .query_typed(
            "INSERT INTO session_revocations (user_id, scope, not_before, reason, expires_at) \
             VALUES ($1, 'all', now(), 'test', now() + interval '1 hour')",
            &[(&user, Type::INT8)],
        )
        .await
        .unwrap();
    e.sessions.as_ref().unwrap().refresh_once().await.unwrap();
    let (status, _, hit) = e.post(&token, &body).await;
    assert_eq!((status, hit), (401, false), "revoked");
    // A single-token (jti) revocation of a fresh token.
    let fresh = e.token(e.b.user, |c| c["iat"] = json!(now() + 1));
    e.owner
        .query_typed(
            "INSERT INTO session_revocations (user_id, scope, jti, not_before, reason, expires_at) \
             VALUES ($1, 'jti', $2, now() - interval '1 hour', 'test', now() + interval '1 hour')",
            &[(&e.b.user, Type::INT8), (&format!("jti-{}", e.b.user), Type::TEXT)],
        )
        .await
        .unwrap();
    e.sessions.as_ref().unwrap().refresh_once().await.unwrap();
    let (status, _, hit) = e
        .post(&fresh, &seen_body(e.b.mailbox, e.b.inbox_only, SEEN))
        .await;
    assert_eq!((status, hit), (401, false), "jti revoked");
    assert!(!e.is_read(msg).await && !e.is_read(e.b.inbox_only).await);
});

db_case!(guest_claim_and_guest_satellite_both_defer_to_go, |e| {
    e.toggle("feature.rust_inbox_list", true).await;
    let args = format!(r#""filter":{{"inMailbox":"{}"}}"#, e.a.inbox);
    let body = list_body(e.a.mailbox, &args);
    let member = e.token(e.a.user, |_| {});
    assert_eq!(e.post(&member, &body).await.0, 200, "member control");
    let guest = e.token(e.a.user, |claims| claims["acct"] = json!("guest"));
    assert_eq!(e.post(&guest, &body).await, (299, "from go".into(), true));

    // Deliberately inconsistent legacy data makes the satellite check
    // discriminating: the token claims member and the mailbox exists.
    e.owner
        .query_typed(
            "INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, status) \
             VALUES ($1, 'guest@example.test', 'inviter@example.test', $2, 'active')",
            &[(&e.a.user, Type::INT8), (&e.a.domain, Type::INT8)],
        )
        .await
        .unwrap();
    assert_eq!(e.post(&member, &body).await, (299, "from go".into(), true));
});

db_case!(
    unconfigured_legacy_keys_forward_whole_requests,
    |e| {
        e.toggle("feature.rust_mark_read", true).await;
        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = captured.clone();
        let upstream = common::fake_upstream(move |req| {
            let sink = sink.clone();
            async move {
                let (parts, body) = req.into_parts();
                let bytes = body.collect().await.unwrap().to_bytes();
                sink.lock().await.push((
                    parts.method,
                    parts.uri.path_and_query().unwrap().as_str().to_owned(),
                    parts
                        .headers
                        .get("authorization")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    ["host", "origin", "content-type", "x-test-header"].map(|name| {
                        parts
                            .headers
                            .get_all(name)
                            .iter()
                            .map(|value| value.to_str().unwrap().to_owned())
                            .collect::<Vec<_>>()
                    }),
                    bytes.to_vec(),
                ));
                hyper::Response::builder()
                    .status(299)
                    .body(full("go"))
                    .unwrap()
            }
        })
        .await;
        let doc = json!({ "keys": [jwk(KID, &public(&e.key))] })
            .to_string()
            .into_bytes();
        let keys = Jwks::with_fetch(Box::new(move || {
            let doc = doc.clone();
            Box::pin(async move { Ok(doc) })
        }));
        let route = JmapRoute(Arc::new(JmapCommands {
            services: None,
        worker: None,
            denylist: None,
            exec: e.exec.clone(),
            keys,
            issuer: "mailserver".into(),
        }));
        let gateway = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;
        // Go-minted, Go-verified tokens, not ES256 signatures with a changed alg.
        let vectors: Value =
            serde_json::from_str(include_str!("golden/go-unsupported-tokens.json")).unwrap();
        let hs = vectors["hs256"].as_str().unwrap();
        let sm2 = vectors["sm2"].as_str().unwrap();
        let body = format!("  {} \n", seen_body(e.a.mailbox, e.a.inbox_only, SEEN));
        // This key source has no configured HS256/SM2 keys (credential owner #406/#420).
        let cases = [("HS256", hs), ("SM2", sm2)];
        for (name, token) in cases {
            let authorization = format!("Bearer {token}");
            let req = Request::post("/jmap?opaque=1%2F2")
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("authorization", &authorization)
                .header("x-test-header", "first value")
                .header("x-test-header", "second value")
                .header("content-type", "application/json")
                .body(full(body.clone()))
                .unwrap();
            let resp = common::send(gateway, req).await;
            assert_eq!(resp.status(), 299, "{name}");
            let got = captured.lock().await.pop().expect("forwarded request");
            assert_eq!(
                got,
                (
                    hyper::Method::POST,
                    "/jmap?opaque=1%2F2".into(),
                    authorization,
                    [
                        vec!["mail.test".into()],
                        vec!["http://mail.test".into()],
                        vec!["application/json".into()],
                        vec!["first value".into(), "second value".into()],
                    ],
                    body.as_bytes().to_vec()
                ),
                "{name}"
            );
        }
        assert!(!e.is_read(e.a.inbox_only).await);
    }
);

db_case!(recorded_go_auth_responses_survive_deferral, |e| {
    let goldens: Value =
        serde_json::from_str(include_str!("golden/go-auth-responses.json")).unwrap();
    e.toggle("feature.rust_mark_read", true).await;
    let guest = e.active_guest().await;
    let before = fixture::snapshot(&e.owner, e.a.mailbox).await.unwrap();
    let audit_before = e.audit_rows(e.a.mailbox).await;
    let db = Db::for_case("auth_golden_notify").expect("db gate already passed");
    let mut notifications = db.listen(&format!("tag:{}", e.a.mailbox)).await.unwrap();
    assert!(notifications.drain(&e.owner).await.unwrap().is_empty());
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let recorded = goldens.clone();
    let upstream = common::fake_upstream(move |req| {
        let name = req.headers()["x-golden-case"].to_str().unwrap().to_owned();
        let golden = recorded[&name].clone();
        counter.fetch_add(1, Ordering::SeqCst);
        async move {
            let mut response =
                hyper::Response::builder().status(golden["status"].as_u64().unwrap() as u16);
            for (name, values) in golden["headers"].as_object().unwrap() {
                for value in values.as_array().unwrap() {
                    response = response.header(name.as_str(), value.as_str().unwrap());
                }
            }
            response
                .body(full(golden["body"].as_str().unwrap().to_owned()))
                .unwrap()
        }
    })
    .await;
    let doc = json!({ "keys": [jwk(KID, &public(&e.key))] })
        .to_string()
        .into_bytes();
    let keys = Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    }));
    let route = JmapRoute(Arc::new(JmapCommands {
        services: None,
        worker: None,
        denylist: None,
        exec: e.exec.clone(),
        keys,
        issuer: "mailserver".into(),
    }));
    let gateway = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;
    e.owner.query_typed(
        "INSERT INTO session_revocations (user_id, scope, jti, not_before, reason, expires_at) \
         VALUES ($1, 'jti', $2, now(), 'golden', now()+interval '1 hour')",
        &[(&e.a.user, Type::INT8), (&format!("jti-{}", e.a.user), Type::TEXT)],
    ).await.unwrap();
    let cases = [
        (
            "expired",
            e.token(e.a.user, |c| {
                c["exp"] = json!(now() - 1);
                c["jti"] = json!("expired-not-revoked");
            }),
        ),
        (
            "wrong_audience",
            e.token(e.a.user, |c| {
                c["aud"] = json!(["wrong-audience"]);
                c["jti"] = json!("audience-not-revoked");
            }),
        ),
        ("guest", e.token(guest, |c| c["acct"] = json!("guest"))),
        ("denylisted", e.token(e.a.user, |_| {})),
    ];
    for (index, (name, token)) in cases.into_iter().enumerate() {
        let request = Request::post("/jmap")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("x-request-id", "gofree-t5-golden")
            .header("x-golden-case", name)
            .body(full(seen_body(e.a.mailbox, e.a.inbox_only, SEEN)))
            .unwrap();
        let response = common::send(gateway, request).await;
        let golden = &goldens[name];
        assert_eq!(
            golden["effects"],
            json!({
                "mailbox_unchanged": true,
                "audit_delta": 0,
                "notifications": [],
            }),
            "{name}: Go effects"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            index + 1,
            "{name} was deferred"
        );
        assert_eq!(
            response.status().as_u16(),
            golden["status"].as_u64().unwrap() as u16,
            "{name}"
        );
        for (header, expected) in golden["headers"].as_object().unwrap() {
            let actual: Vec<_> = response
                .headers()
                .get_all(header.as_str())
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect();
            let expected: Vec<_> = expected
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            assert_eq!(actual, expected, "{name}: {header}");
        }
        let observed: std::collections::BTreeSet<_> = response
            .headers()
            .keys()
            .map(|name| name.as_str())
            .filter(|name| {
                !matches!(
                    *name,
                    "date"
                        | "connection"
                        | "transfer-encoding"
                        | "keep-alive"
                        | "proxy-authenticate"
                        | "proxy-authorization"
                        | "te"
                        | "trailer"
                        | "upgrade"
                )
            })
            .collect();
        let expected: std::collections::BTreeSet<_> = golden["headers"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(observed, expected, "{name}: response header names");
        assert_eq!(
            // Go authserver bytes replayed by the fake upstream, not Rust-written.
            common::body_bytes_unchecked(response).await.as_ref(),
            golden["body"].as_str().unwrap().as_bytes(),
            "{name}"
        );
    }
    assert_eq!(
        fixture::snapshot(&e.owner, e.a.mailbox).await.unwrap(),
        before
    );
    assert_eq!(e.audit_rows(e.a.mailbox).await, audit_before);
    assert!(notifications.drain(&e.owner).await.unwrap().is_empty());
});

db_case!(mailbox_scope_comes_only_from_the_verified_identity, |e| {
    e.toggle("feature.rust_mark_read", true).await;
    let token = e.token(e.a.user, |_| {});
    // Account denials belong to Rust under either retired flag value.
    let recorded: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/jmap/goldens/email-set-cross-tenant.json"
    ))
    .unwrap();
    let expected = retarget(
        recorded["observation"]["response"]["body"]
            .as_str()
            .unwrap(),
        &[("sessionState", Str(&e.session_state(e.a.user).await))],
    );
    for enabled in [false, true] {
        e.toggle("feature.rust_mark_read", enabled).await;
        let (status, body, hit) = e
            .post(&token, &seen_body(e.b.mailbox, e.b.inbox_only, SEEN))
            .await;
        assert_eq!((status, hit), (200, false), "account denial flag={enabled}");
        assert_eq!(body, expected);
    }
    // A's own account naming B's message: served, the reducer's notFound.
    let (status, body, hit) = e
        .post(&token, &seen_body(e.a.mailbox, e.b.inbox_only, SEEN))
        .await;
    assert_eq!((status, hit), (200, false));
    let state = fixture::snapshot(&e.owner, e.a.mailbox)
        .await
        .unwrap()
        .email_state
        .to_string();
    let expected = retarget(
        &retarget_item(golden::SET_NOTFOUND, "notUpdated", e.b.inbox_only),
        &[
            ("sessionState", Str(&e.session_state(e.a.user).await)),
            ("accountId", Str(&e.a.mailbox.to_string())),
            ("newState", Str(&state)),
            ("oldState", Str(&state)),
        ],
    );
    assert_eq!(body, expected);
    assert!(!e.is_read(e.b.inbox_only).await, "B's message untouched");
});

// Review item 6 (+a): a per-item reducer error (the reducer catches the
// failure, rolls its subtransaction back and reports `invalidArguments`) is
// committed and answered exactly as Go answers it: a per-item `notUpdated`
// entry (Go's captured bytes), the audit row written, no data or state change.
db_case!(a_reducer_item_error_is_answered_as_go_answers_it, |e| {
    e.toggle("feature.rust_mark_read", true).await;
    let token = e.token(e.a.user, |_| {});
    let (mb, msg) = (e.a.mailbox, e.a.inbox_only);
    let (func, trig) = (format!("t6_refuse_{msg}"), format!("t6_refuse_{msg}"));
    e.owner
        .batch_execute(&format!(
            "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.id = {msg} THEN RAISE EXCEPTION 'refused' USING ERRCODE = 'P0001'; END IF; \
             RETURN NEW; END $$; \
             CREATE TRIGGER {trig} BEFORE UPDATE ON messages FOR EACH ROW EXECUTE FUNCTION {func}();"
        ))
        .await
        .unwrap();
    let before = fixture::snapshot(&e.owner, mb).await.unwrap();
    let audit = e.audit_rows(mb).await;
    let state = e.session_state(e.a.user).await;
    let (status, body, hit) = e.post(&token, &seen_body(mb, msg, SEEN)).await;
    e.owner
        .batch_execute(&format!(
            "DROP TRIGGER {trig} ON messages; DROP FUNCTION {func}();"
        ))
        .await
        .unwrap();
    let after = fixture::snapshot(&e.owner, mb).await.unwrap();
    assert_eq!((status, hit), (200, false));
    let st = before.email_state.to_string();
    let expected = retarget(
        &retarget_item(golden::SET_INVALID, "notUpdated", msg),
        &[
            ("sessionState", Str(&state)),
            ("accountId", Str(&mb.to_string())),
            ("newState", Str(&st)),
            ("oldState", Str(&st)),
        ],
    );
    assert_eq!(body, expected);
    assert_eq!(after, before, "no data, counter or state change");
    assert_eq!(
        e.audit_rows(mb).await,
        audit + 1,
        "committed, audited as Go"
    );
});

// Security admission still reads the registry state. A stalled read gets one
// pre-check bound, writes nothing, and recovers once the lock is released.
db_case!(
    a_blocked_security_read_forwards_within_one_precheck_bound,
    |e| {
        let token = e.token(e.a.user, |_| {});
        let (mb, msg) = (e.a.mailbox, e.a.inbox_only);
        let db =
            Db::for_case("a_blocked_security_read_forwards_within_one_precheck_bound").unwrap();
        let mut locker = db.connect().await.unwrap();
        let tx = locker.transaction().await.unwrap();
        tx.batch_execute("LOCK TABLE feature_toggle_registry_state IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let t = std::time::Instant::now();
        let (status, body, hit) = e.post(&token, &seen_body(mb, msg, SEEN)).await;
        let took = t.elapsed();
        tx.rollback().await.unwrap();
        assert_eq!((status, body.as_str(), hit), (299, "from go", true));
        // The bound is 1 s in production; the DB-backed harness widens it for starved hosts.
        let bound = setjoin_authz::precheck_timeout() + std::time::Duration::from_secs(2);
        assert!(took < bound, "took {took:?}, bound {bound:?}");
        assert!(!e.is_read(msg).await, "Rust wrote nothing");
        let (status, _, hit) = e.post(&token, &seen_body(mb, msg, SEEN)).await;
        assert_eq!((status, hit), (200, false), "served again after the lock");
    }
);

// The front door owns Go's coarse budget regardless of retired pilot flags
// or method security gates. Go's captured 429 remains the public response.
db_case!(
    a_spent_front_door_budget_is_independent_of_pilot_flags,
    |e| {
        let upstream = common::fake_upstream(|_req| async {
            hyper::Response::builder()
                .status(299)
                .body(full("from go"))
                .unwrap()
        })
        .await;
        let gw = common::gateway_limited(
            upstream,
            RouteTable::proxy_all(),
            EdgeLimit::for_front_door(Limiter::new(0, 60)),
        )
        .await;
        for seen_flag in [false, true] {
            e.toggle("feature.rust_mark_read", seen_flag).await;
            for list_flag in [false, true] {
                e.toggle("feature.rust_inbox_list", list_flag).await;
                for security_gate in [false, true] {
                    e.toggle("feature.cae_runtime", security_gate).await;
                    let req = Request::get("/api/settings")
                        .header("host", "mail.test")
                        .body(full(""))
                        .unwrap();
                    let resp = common::send(gw, req).await;
                    assert_eq!(
                        resp.status(),
                        429,
                        "seen={seen_flag}, list={list_flag}, security={security_gate}"
                    );
                    assert_eq!(
                        &common::body_bytes(resp).await[..],
                        include_bytes!("golden/go-rate-limited.json")
                    );
                }
            }
        }
    }
);

db_case!(runtime_security_gates_answer_natively_before_jmap, |e| {
    e.toggle("feature.rust_inbox_list", true).await;
    let token = e.token(e.a.user, |_| {});
    for gate in [
        "feature.cae_runtime",
        "feature.device_trust_enforcement",
        "feature.device_lockdown",
    ] {
        e.toggle(gate, true).await;
        let (status, _, hit) = e
            .post(&token, &list_body(e.a.mailbox, &format!(r#""filter":{{"inMailbox":"{}"}}"#, e.a.inbox)))
            .await;
        let expected = if gate == "feature.device_trust_enforcement" { 403 } else { 200 };
        assert_eq!((status, hit), (expected, false), "{gate}");
        e.toggle(gate, false).await;
    }
    // Cross-site browser request: Go's CSRF check would refuse it.
    let req = Request::post("/jmap")
        .header("host", "mail.test")
        .header("origin", "http://evil.test")
        .header("authorization", format!("Bearer {token}"))
        .body(full(seen_body(e.a.mailbox, e.a.inbox_only, SEEN)))
        .unwrap();
    let before = e.upstream_hits.load(Ordering::SeqCst);
    let resp = common::send(e.gateway, req).await;
    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(common::body_bytes(resp).await, "{\"detail\":\"CSRF validation failed\",\"status\":403,\"title\":\"csrf_failed\",\"type\":\"about:blank\"}\n");
    assert_eq!(e.upstream_hits.load(Ordering::SeqCst), before);
    assert!(!e.is_read(e.a.inbox_only).await);
});

// ── native inbox-list and general Email/query (#216/#315) ──

/// The `Email/query` body `inboxStore.loadEmails` sends.
fn list_body(account: i64, args: &str) -> String {
    format!(
        r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{{"accountId":"{account}",{args}}},"0"]]}}"#
    )
}

impl Env {
    /// Frozen-Go success bytes, with only fixture identity and state substituted.
    async fn go_set_updated_bytes(&self, msg: i64, old: i64, new: i64) -> String {
        retarget(
            golden::SET_UPDATED,
            &[
                ("sessionState", Str(&self.session_state(self.a.user).await)),
                ("accountId", Str(&self.a.mailbox.to_string())),
                ("oldState", Str(&old.to_string())),
                ("newState", Str(&new.to_string())),
                ("updated", Array(&msg.to_string())),
            ],
        )
    }

    /// The Go path's answer for `Email/query` `args` as `user`: the values
    /// from the reducer called as `emailQuery` calls it (CallScoped, raw
    /// filter/sort JSON, Go-clamped limit), in Go's own captured bytes
    /// (golden `go-list-1.json`) re-targeted at them.
    async fn go_list_bytes(&self, user: i64, mailbox: i64, args: &str) -> String {
        let v: Value = serde_json::from_str(&format!("{{{args}}}")).unwrap();
        let filter = v.get("filter").map(Value::to_string);
        let sort = v.get("sort").map(Value::to_string);
        let position = v.get("position").and_then(Value::as_i64).unwrap_or(0) as i32;
        let limit = match v.get("limit").and_then(Value::as_i64).unwrap_or(0) {
            n if n <= 0 || n > 256 => 50,
            n => n as i32,
        };
        let state = self.session_state(user).await;
        let mut c = db_owner(self).await;
        let tx = c.transaction().await.unwrap();
        tx.query_typed(
            "SELECT set_config('app.current_mailbox_id', $1, true)",
            &[(&mailbox.to_string(), Type::TEXT)],
        )
        .await
        .unwrap();
        let raw: String = tx
            .query_typed(
                "SELECT jmap_email_query($1, $2::jsonb, $3::jsonb, $4, $5)::text",
                &[
                    (&mailbox, Type::INT8),
                    (&filter, Type::TEXT),
                    (&sort, Type::TEXT),
                    (&position, Type::INT4),
                    (&limit, Type::INT4),
                ],
            )
            .await
            .unwrap()[0]
            .get(0);
        tx.commit().await.unwrap();
        let r: Value = serde_json::from_str(&raw).unwrap();
        let ids: Vec<String> = r["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| format!("\"{}\"", id.as_str().unwrap()))
            .collect();
        let ids = ids.join(",");
        retarget(
            golden::LIST_PAGE,
            &[
                ("sessionState", Str(&state)),
                ("ids", Array(&ids)),
                ("state", Str(r["state"].as_str().unwrap())),
                ("total", Num(r["total"].as_i64().unwrap())),
                ("position", Num(r["position"].as_i64().unwrap())),
                ("accountId", Str(r["accountId"].as_str().unwrap())),
            ],
        )
    }

    async fn audit_rows(&self, mailbox: i64) -> i64 {
        self.owner
            .query_typed(
                "SELECT count(*) FROM mailbox_audit_log WHERE mailbox_id = $1",
                &[(&mailbox, Type::INT8)],
            )
            .await
            .unwrap()[0]
            .get(0)
    }
}

/// A second owner client (the reducer call needs `&mut` for its transaction).
async fn db_owner(_: &Env) -> Client {
    let db = Db::for_case("go_list_bytes").expect("db gate already passed");
    db.connect().await.expect("owner connection")
}

db_case!(
    email_queries_match_go_with_every_pilot_flag_combination,
    |e| {
        let token = e.token(e.a.user, |_| {});
        let (mb, inbox, msg) = (e.a.mailbox, e.a.inbox, e.a.inbox_only);
        // Establish a read message; each matrix entry repeats that no-op as Go does.
        assert_eq!(e.post(&token, &seen_body(mb, msg, SEEN)).await.0, 200);
        let before = fixture::snapshot(&e.owner, mb).await.unwrap();
        let expected_seen = e
            .go_set_updated_bytes(msg, before.email_state, before.email_state)
            .await;
        let cases = [
            format!(r#""filter":{{"inMailbox":"{inbox}"}}"#),
            format!(r#""filter":{{"inMailbox":"{inbox}","text":"hello"}}"#),
            format!(
                r#""filter":{{"inMailbox":"{inbox}"}},"sort":[{{"property":"subject","isAscending":true}}]"#
            ),
            r#""filter":{"inArchive":true}"#.to_owned(),
        ];
        // Go reports invalid SQL paging as a method error, still served by Rust.
        let failure: Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/jmap/goldens/email-query-bad-date.json"
        ))
        .unwrap();
        let expected_failure = retarget(
            failure["observation"]["response"]["body"].as_str().unwrap(),
            &[("sessionState", Str(&e.session_state(e.a.user).await))],
        );
        for seen_flag in [false, true] {
            e.toggle("feature.rust_mark_read", seen_flag).await;
            for list_flag in [false, true] {
                e.toggle("feature.rust_inbox_list", list_flag).await;
                let audit = e.audit_rows(mb).await;
                for args in &cases {
                    let expected = e.go_list_bytes(e.a.user, mb, args).await;
                    let (status, body, hit) = e.post(&token, &list_body(mb, args)).await;
                    assert_eq!(
                        (status, hit),
                        (200, false),
                        "seen={seen_flag}, list={list_flag}: {args}"
                    );
                    assert_eq!(body, expected, "seen={seen_flag}, list={list_flag}: {args}");
                }
                let invalid = format!(r#""filter":{{"inMailbox":"{inbox}"}},"position":-1"#);
                let (status, body, hit) = e.post(&token, &list_body(mb, &invalid)).await;
                assert_eq!(
                    (status, hit),
                    (200, false),
                    "invalid paging seen={seen_flag}, list={list_flag}"
                );
                assert_eq!(body, expected_failure);
                assert_eq!(e.audit_rows(mb).await, audit, "queries write no audit");
                let (status, body, hit) = e.post(&token, &seen_body(mb, msg, SEEN)).await;
                assert_eq!(
                    (status, hit),
                    (200, false),
                    "seen={seen_flag}, list={list_flag}"
                );
                assert_eq!(body, expected_seen);
                assert_eq!(e.audit_rows(mb).await, audit + 1, "one no-op write audit");
            }
        }
        assert_eq!(fixture::snapshot(&e.owner, mb).await.unwrap(), before);

        // Both query adapters deny another account natively under every flag value.
        let recorded: Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/jmap/goldens/email-query-cross-tenant.json"
        ))
        .unwrap();
        let expected = retarget(
            recorded["observation"]["response"]["body"]
                .as_str()
                .unwrap(),
            &[("sessionState", Str(&e.session_state(e.a.user).await))],
        );
        for seen_flag in [false, true] {
            e.toggle("feature.rust_mark_read", seen_flag).await;
            for list_flag in [false, true] {
                e.toggle("feature.rust_inbox_list", list_flag).await;
                for args in [
                    r#""filter":{"text":"hello"}"#.to_owned(),
                    format!(r#""filter":{{"inMailbox":"{}"}}"#, e.b.inbox),
                ] {
                    let (status, body, hit) = e.post(&token, &list_body(e.b.mailbox, &args)).await;
                    assert_eq!(
                        (status, hit),
                        (200, false),
                        "account denial seen={seen_flag}, list={list_flag}: {args}"
                    );
                    assert_eq!(body, expected);
                }
            }
        }

        // Security admission still applies to lists independently of pilot flags.
        e.toggle("feature.cae_runtime", true).await;
        let (status, body, hit) = e.post(&token, &list_body(mb, &cases[0])).await;
        assert_eq!((status, hit), (200, false));
        assert_eq!(body, e.go_list_bytes(e.a.user, mb, &cases[0]).await);
        assert_eq!(fixture::snapshot(&e.owner, mb).await.unwrap(), before);
    }
);

db_case!(list_flag_on_answers_with_the_go_path_bytes, |e| {
    e.toggle("feature.rust_inbox_list", true).await;
    let token = e.token(e.a.user, |_| {});
    let (mb, inbox, user) = (e.a.mailbox, e.a.inbox, e.a.user);
    let trash: i64 = e
        .owner
        .query_typed(
            "SELECT id FROM tags WHERE mailbox_id = $1 AND name = 'Trash'",
            &[(&mb, Type::INT8)],
        )
        .await
        .unwrap()[0]
        .get(0);
    let sort = r#""sort":[{"property":"receivedAt","isAscending":false}]"#;
    let cases = [
        // the webmail's first Inbox page
        format!(r#""filter":{{"inMailbox":"{inbox}","focus":"focused"}},{sort},"limit":50"#),
        // load-more boundaries: a page of one, the last, and past the end
        format!(r#""filter":{{"inMailbox":"{inbox}"}},{sort},"limit":1,"position":1"#),
        format!(r#""filter":{{"inMailbox":"{inbox}"}},{sort},"limit":1,"position":2"#),
        format!(r#""filter":{{"inMailbox":"{inbox}"}},{sort},"limit":50,"position":500"#),
        // unread / read filters, oldest first, Other pile, empty tag
        format!(r#""filter":{{"inMailbox":"{inbox}","hasKeyword":"$unseen"}}"#),
        format!(r#""filter":{{"inMailbox":"{inbox}","hasKeyword":"$seen"}}"#),
        format!(
            r#""filter":{{"inMailbox":"{inbox}"}},"sort":[{{"property":"receivedAt","isAscending":true}}]"#
        ),
        format!(r#""filter":{{"inMailbox":"{inbox}","focus":"other"}}"#),
        format!(r#""filter":{{"inMailbox":"{trash}"}},"limit":0"#),
        // another mailbox's tag under A's own account: nothing, never B's rows
        format!(r#""filter":{{"inMailbox":"{}"}}"#, e.b.inbox),
    ];
    let before = fixture::snapshot(&e.owner, mb).await.unwrap();
    let audit = e.audit_rows(mb).await;
    for args in &cases {
        let expected = e.go_list_bytes(user, mb, args).await;
        let (status, body, hit) = e.post(&token, &list_body(mb, args)).await;
        assert_eq!((status, hit), (200, false), "{args}");
        assert_eq!(body, expected, "{args}");
    }
    // Non-vacuous: the first page holds the fixture's two Inbox messages,
    // newest (`inbox_only`, inserted last) first.
    let (_, first, _) = e.post(&token, &list_body(mb, &cases[0])).await;
    assert!(
        first.contains(&format!(
            "\"ids\":[\"{}\",\"{}\"],\"state\":\"{}\",\"total\":2,\"position\":0,\"accountId\":\"{mb}\"",
            e.a.inbox_only, e.a.two_labels, before.email_state
        )),
        "{first}"
    );
    // Unread flags move with a read made elsewhere; still byte-equal.
    e.owner
        .query_typed(
            "UPDATE messages SET is_read = TRUE WHERE id = $1",
            &[(&e.a.inbox_only, Type::INT8)],
        )
        .await
        .unwrap();
    let after_read = fixture::snapshot(&e.owner, mb).await.unwrap();
    for args in &cases[4..6] {
        let expected = e.go_list_bytes(user, mb, args).await;
        let (_, body, hit) = e.post(&token, &list_body(mb, args)).await;
        assert!(!hit);
        assert_eq!(body, expected, "{args}");
    }
    // Listing wrote nothing: no mark-read, state, journal or audit row.
    assert_eq!(fixture::snapshot(&e.owner, mb).await.unwrap(), after_read);
    assert_eq!(after_read.email_state, before.email_state);
    assert_eq!(e.audit_rows(mb).await, audit);
});

// The S/MIME decrypt-on-read helper belongs to #328. This unported shape,
// rather than general query filters or ordinary patches, still forwards whole.
db_case!(
    encrypted_email_get_forwards_without_effects_for_either_pilot_flag,
    |e| {
        let token = e.token(e.a.user, |_| {});
        let (mb, msg) = (e.a.mailbox, e.a.inbox_only);
        e.owner.query_typed(
        "UPDATE messages SET crypto_type = 'smime-encrypted' WHERE id = $1 AND mailbox_id = $2",
        &[(&msg, Type::INT8), (&mb, Type::INT8)],
    ).await.unwrap();
        let request = format!(
            r#"{{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/get",{{"accountId":"{mb}","ids":["{msg}"]}},"0"]]}}"#
        );
        let before = fixture::snapshot(&e.owner, mb).await.unwrap();
        let audit = e.audit_rows(mb).await;
        for enabled in [false, true] {
            e.toggle("feature.rust_mark_read", enabled).await;
            e.toggle("feature.rust_inbox_list", enabled).await;
            let (status, body, hit) = e.post(&token, &request).await;
            assert_eq!(
                (status, body.as_str(), hit),
                (299, "from go", true),
                "flag={enabled}"
            );
            assert_eq!(fixture::snapshot(&e.owner, mb).await.unwrap(), before);
            assert_eq!(
                e.audit_rows(mb).await,
                audit,
                "no Rust email_get audit before forwarding"
            );
        }
    }
);
