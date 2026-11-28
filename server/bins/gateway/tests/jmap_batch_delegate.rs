//! Wave 1 (#356) integration tests:
//! 1. HTTP transport errors (`400` `notJSON`/`notRequest`/`requestTooLarge`/`unknownCapability`),
//!    10 MB `JMAP_BODY_CAP`, and auth-first untouched forwarding (`299`).
//! 2. Multi-call HTTP batches, `#resultReference`, `createdIds`, 0-call envelope parity,
//!    and distinct per-call `OperationId`s.
//! 3. Ordered preflight before Call 0 (zero partial writes / zero Rust audits).
//! 4. Non-Family delegated accounts permission matrix under V090 FORCE-RLS (`setjoin_app`).
use crate::common;

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
use setjoin_gateway::jmap::{JmapCommands, JmapRoute, JmapServices};
use setjoin_gateway::RouteTable;
use setjoin_pg::ScopedExecutor;
use tokio::sync::Mutex;
use tokio_postgres::types::Type;
use tokio_postgres::Client;

use common::{full, BoxError};

static SERIAL: Mutex<()> = Mutex::const_new(());
const KID: &str = "test-es256-wave1";
const TOGGLES: [&str; 6] = [
    "feature.cae_runtime",
    "feature.device_trust_enforcement",
    "feature.conditional_access",
    "feature.device_lockdown",
    "feature.client_recovery_receipts",
    "feature.stale_nudges",
];

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn public(key: &SigningKey) -> setjoin_gateway::jmap::token::VerifyingKey {
    setjoin_gateway::jmap::token::VerifyingKey::from_sec1(
        key.verifying_key().to_sec1_point(false).as_bytes(),
    )
    .unwrap()
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

struct Env {
    owner: Client,
    exec: ScopedExecutor,
    dsn: String,
    app_dsn: Option<String>,
    gateway: std::net::SocketAddr,
    upstream_hits: Arc<AtomicUsize>,
    key: SigningKey,
    a: Account,
    b: Account,
    saved: Vec<(String, Option<bool>)>,
}

async fn env(db: &Db) -> Env {
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
        owner
            .query_typed(
                "INSERT INTO feature_toggles (key, enabled) VALUES ($1, FALSE) \
                 ON CONFLICT (key) DO UPDATE SET enabled = FALSE",
                &[(&key, Type::TEXT)],
            )
            .await
            .unwrap();
    }
    let a = fixture::account(&owner, "w1-a").await.expect("fixture a");
    let b = fixture::account(&owner, "w1-b").await.expect("fixture b");

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

    let key = SigningKey::from_slice(&[0x33; 32]).unwrap();
    let doc = json!({ "keys": [jwk(KID, &public(&key))] })
        .to_string()
        .into_bytes();
    let jwks = Arc::new(Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    })));
    let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).expect("pool");
    let worker = ScopedExecutor::from_dsn(&db.dsn, 2).expect("worker pool");
    let services = Arc::new(JmapServices::new(
        worker.clone(),
        "mail.test".into(),
        52_428_800,
    ));
    let route = JmapRoute(Arc::new(JmapCommands {
        services: Some(services),
        exec: exec.clone(),
        worker: Some(worker),
        denylist: None,
        keys: jwks.clone(),
        issuer: "mailserver".into(),
    }));
    let worker_db = setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap();
    let runtime = setjoin_gateway::runtime_access::RuntimeAccess::new(
        exec.clone(),
        jwks,
        "mailserver".into(),
    )
    .with_workers(ScopedExecutor::from_dsn(&db.dsn, 2).unwrap(), worker_db)
    .with_direct(db.direct.clone());
    let routes = RouteTable::proxy_all().with(route).with_runtime(runtime);
    let gateway = common::gateway_limited(
        upstream,
        routes,
        EdgeLimit::for_front_door(Limiter::new(600, 60)),
    )
    .await;
    Env {
        owner,
        exec,
        dsn: db.dsn.clone(),
        app_dsn: db.app.clone(),
        gateway,
        upstream_hits: hits,
        key,
        a,
        b,
        saved,
    }
}

impl Env {
    fn token(&self, user: i64) -> String {
        let claims = json!({
            "uid": user,
            "email": format!("u{user}@test"),
            "typ": "access",
            "jti": format!("jti-{user}"),
            "fam": format!("fam-{user}"),
            "iss": "mailserver",
            "aud": ["mailserver-gateway"],
            "iat": now() - 10,
            "exp": now() + 600,
        });
        sign(
            &self.key,
            &json!({"alg": "ES256", "kid": KID, "typ": "JWT"}),
            &claims,
        )
    }

    async fn post_raw(&self, auth: Option<&str>, body: &str) -> (u16, String, String, bool) {
        let before = self.upstream_hits.load(Ordering::SeqCst);
        let mut builder = Request::post("/jmap")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("content-type", "application/json");
        if let Some(token) = auth {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let req = builder.body(full(body.to_owned())).unwrap();
        let resp = common::send(self.gateway, req).await;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let hit = self.upstream_hits.load(Ordering::SeqCst) > before;
        (
            status,
            content_type,
            String::from_utf8(bytes.to_vec()).unwrap(),
            hit,
        )
    }

    async fn post(&self, token: &str, body: &str) -> (u16, String, bool) {
        let (status, _, text, hit) = self.post_raw(Some(token), body).await;
        (status, text, hit)
    }

    async fn grant(&self, target_mailbox: i64, delegate_user: i64, granted_by: i64, perm: &str) {
        self.owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2",
                &[&target_mailbox, &delegate_user],
            )
            .await
            .unwrap();
        self.owner
            .execute(
                "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) VALUES ($1, $2, $3, $4)",
                &[&target_mailbox, &delegate_user, &perm, &granted_by],
            )
            .await
            .unwrap();
    }

    async fn revoke(&self, target_mailbox: i64, delegate_user: i64) {
        self.owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2",
                &[&target_mailbox, &delegate_user],
            )
            .await
            .unwrap();
    }

    async fn set_suspended(&self, mailbox: i64, suspended: bool) {
        self.owner
            .execute(
                "UPDATE mailboxes SET enabled = $2 WHERE id = $1",
                &[&mailbox, &!suspended],
            )
            .await
            .unwrap();
        let state = if suspended { "suspended" } else { "active" };
        self.owner
            .execute(
                "UPDATE mailbox_lifecycle SET access_state = $2, generation = generation + 1, \
                 updated_at = statement_timestamp() \
                 WHERE mailbox_id = $1 AND binding_state IN ('bound', 'shared')",
                &[&mailbox, &state],
            )
            .await
            .unwrap();
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

    async fn close(self) {
        for (key, value) in &self.saved {
            match value {
                Some(v) => {
                    self.owner
                        .query_typed(
                            "INSERT INTO feature_toggles (key, enabled) VALUES ($1, $2) \
                             ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled",
                            &[(key, Type::TEXT), (v, Type::BOOL)],
                        )
                        .await
                        .unwrap();
                }
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
        let _ = self.set_suspended(self.a.mailbox, false).await;
        let _ = self.set_suspended(self.b.mailbox, false).await;
        for mb in [self.a.mailbox, self.b.mailbox] {
            for table in ["outbound_queue_hot", "outbound_queue"] {
                let _ = self
                    .owner
                    .query_typed(
                        &format!("DELETE FROM {table} WHERE mailbox_id=$1"),
                        &[(&mb, Type::INT8)],
                    )
                    .await;
            }
        }
        let _ = self
            .owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = ANY($1)",
                &[&vec![self.a.mailbox, self.b.mailbox]],
            )
            .await;
        fixture::remove(&self.owner, &self.a).await.unwrap();
        fixture::remove(&self.owner, &self.b).await.unwrap();
    }
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

macro_rules! wave1_case {
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

wave1_case!(http_transport_errors_and_auth_first_forwarding, |e| {
    // 1. Auth-first: unauthenticated or unsupported JWTs answer native 401 before body parsing,
    // while Basic credentials still forward untouched (#355).
    let vectors: Value =
        serde_json::from_str(include_str!("golden/go-unsupported-tokens.json")).unwrap();
    let hs256 = vectors["hs256"].as_str().unwrap();
    for (label, auth, body) in [
        ("missing auth + bad json", None, "{"),
        ("garbage token + bad json", Some("a.b.c"), "{"),
        ("hs256 token + null", Some(hs256), "null"),
    ] {
        let (status, _, _, hit) = e.post_raw(auth, body).await;
        assert_eq!((status, hit), (401, false), "{label}");
    }
    let before = e.upstream_hits.load(Ordering::SeqCst);
    let basic_req = Request::post("/jmap")
        .header("host", "mail.test")
        .header("origin", "http://mail.test")
        .header("content-type", "application/json")
        .header("authorization", "Basic dXNlcjpwYXNz")
        .body(full("{".to_owned()))
        .unwrap();
    let basic_resp = common::send(e.gateway, basic_req).await;
    assert_eq!(basic_resp.status().as_u16(), 401);
    assert_eq!(
        basic_resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some(r#"Negotiate, Bearer realm="mailserver""#)
    );
    assert_eq!(e.upstream_hits.load(Ordering::SeqCst), before);

    let token = e.token(e.a.user);

    // 2. Verified caller: malformed / non-object / trailing / bad-typed -> 400 notJSON.
    for bad in [
        "{",
        "[1]",
        r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[]} extra"#,
        r#"{"using":"core","methodCalls":[]}"#,
        r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{}]]}"#,
    ] {
        let (status, ct, text, hit) = e.post_raw(Some(&token), bad).await;
        assert_eq!(
            (status, ct.as_str(), hit),
            (400, "application/problem+json", false),
            "{bad}"
        );
        assert!(text.ends_with('\n'));
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["type"], "urn:ietf:params:jmap:error:notJSON");
        assert_eq!(doc["detail"], "invalid JSON in request body");
    }

    // 3. > 10 MB body -> 400 notJSON (maxSizeRequest).
    let huge = " ".repeat(10_000_001);
    let (status, ct, text, hit) = e.post_raw(Some(&token), &huge).await;
    assert_eq!(
        (status, ct.as_str(), hit),
        (400, "application/problem+json", false)
    );
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["type"], "urn:ietf:params:jmap:error:notJSON");

    // 4. null / empty using -> 400 notRequest.
    for req in ["null", "{}", r#"{"using":[],"methodCalls":[]}"#] {
        let (status, ct, text, hit) = e.post_raw(Some(&token), req).await;
        assert_eq!(
            (status, ct.as_str(), hit),
            (400, "application/problem+json", false),
            "{req}"
        );
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["type"], "urn:ietf:params:jmap:error:notRequest");
        assert_eq!(doc["detail"], "'using' array must not be empty");
    }

    // 5. > 32 calls -> 400 requestTooLarge.
    let calls: Vec<_> = (0..33)
        .map(|i| json!(["Core/echo", {}, format!("c{i}")]))
        .collect();
    let over32 = json!({"using": ["urn:ietf:params:jmap:core"], "methodCalls": calls}).to_string();
    let (status, ct, text, hit) = e.post_raw(Some(&token), &over32).await;
    assert_eq!(
        (status, ct.as_str(), hit),
        (400, "application/problem+json", false)
    );
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["type"], "urn:ietf:params:jmap:error:requestTooLarge");
    assert_eq!(doc["detail"], "maxCallsInRequest of 32 exceeded (33 calls)");

    // 6. Undeclared capability -> 400 unknownCapability.
    let missing_cap = json!({
        "using": ["urn:ietf:params:jmap:core"],
        "methodCalls": [["Email/get", {"accountId": e.a.mailbox.to_string()}, "c0"]]
    })
    .to_string();
    let (status, ct, text, hit) = e.post_raw(Some(&token), &missing_cap).await;
    assert_eq!(
        (status, ct.as_str(), hit),
        (400, "application/problem+json", false)
    );
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["type"], "urn:ietf:params:jmap:error:unknownCapability");
});

wave1_case!(http_multicall_batch_result_ref_and_created_ids, |e| {
    let token = e.token(e.a.user);
    let mb = e.a.mailbox.to_string();

    // 0-call HTTP envelope: always includes methodResponses: [], no @type / requestId / createdIds.
    let (status, empty_body, hit) = e
        .post(
            &token,
            r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[]}"#,
        )
        .await;
    assert_eq!((status, hit), (200, false));
    assert!(empty_body.ends_with('\n'));
    let empty_doc: Value = serde_json::from_str(&empty_body).unwrap();
    assert_eq!(empty_doc["methodResponses"], json!([]));
    assert!(empty_doc.get("@type").is_none());
    assert!(empty_doc.get("requestId").is_none());
    assert!(empty_doc.get("createdIds").is_none());

    // Multi-call batch: Email/query -> Email/get (#ids) -> Mailbox/set (create -> createdIds)
    // -> two Email/set updates -> Core/echo (HTML client_id).
    let batch = json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Email/query", {"accountId": mb, "filter": {"inMailbox": e.a.inbox.to_string()}}, "q0"],
            ["Email/get", {"accountId": mb, "#ids": {"resultOf": "q0", "name": "Email/query", "path": "/ids"}, "properties": ["id"]}, "g0"],
            ["Mailbox/set", {"accountId": mb, "create": {"k1": {"name": "Wave1Folder"}}}, "m0"],
            ["Email/set", {"accountId": mb, "update": {e.a.inbox_only.to_string(): {"keywords": {"$seen": true}}}}, "u0"],
            ["Email/set", {"accountId": mb, "update": {e.a.two_labels.to_string(): {"keywords": {"$flagged": true}}}}, "u1"],
            ["Core/echo", {"ok": true}, "<a>"]
        ]
    })
    .to_string();
    let before_receipts: i64 = e
        .owner
        .query_one("SELECT count(*) FROM rust_operation_receipts", &[])
        .await
        .unwrap()
        .get(0);
    let before_audits = e.audit_rows(e.a.mailbox).await;
    let (status, body, hit) = e.post(&token, &batch).await;
    assert_eq!((status, hit), (200, false));
    assert!(
        body.contains(r#"\u003ca\u003e"#),
        "Go HTML-escaped client_id"
    );
    let doc: Value = serde_json::from_str(&body).unwrap();
    let resps = doc["methodResponses"].as_array().unwrap();
    assert_eq!(resps.len(), 6);
    assert_eq!(resps[0][0], "Email/query");
    assert_eq!(resps[1][0], "Email/get");
    assert_eq!(resps[1][1]["list"].as_array().unwrap().len(), 2);
    assert_eq!(resps[2][0], "Mailbox/set");
    let created_mb = resps[2][1]["created"]["k1"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(doc["createdIds"]["k1"], created_mb);
    assert_eq!(resps[3][0], "Email/set");
    assert_eq!(resps[4][0], "Email/set");
    assert!(
        resps[4][1]["updated"]
            .as_array()
            .is_some_and(|a| a.contains(&json!(e.a.two_labels))),
        "second mutator in batch must commit with its own OperationId: {body}"
    );
    assert_eq!(resps[5][0], "Core/echo");
    assert!(e.is_read(e.a.inbox_only).await);

    let after_receipts: i64 = e
        .owner
        .query_one("SELECT count(*) FROM rust_operation_receipts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        after_receipts,
        before_receipts + 1,
        "Mailbox/set writes 1 rust_operation_receipts row: before={before_receipts}, after={after_receipts}"
    );
    assert_eq!(
        e.audit_rows(e.a.mailbox).await,
        before_audits + 3,
        "Email/get + two Email/set calls write 3 mailbox_audit_log rows"
    );
    let distinct_email_ops: i64 = e
        .owner
        .query_one(
            "SELECT count(DISTINCT details->>'operation') \
             FROM mailbox_audit_log \
             WHERE mailbox_id = $1 AND action = 'email_set' AND details ? 'operation'",
            &[&e.a.mailbox],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        distinct_email_ops, 2,
        "two Email/set mutators in one batch must record 2 distinct OperationIds"
    );
});

wave1_case!(
    preflight_prevents_partial_writes_when_later_call_defers,
    |e| {
        let token = e.token(e.a.user);
        let mb = e.a.mailbox.to_string();

        // Case A (#356 Wave 3): Email/set (seen) followed by Email/set with #create ref
        // runs NATIVELY without deferring to Go: Call 0 marks read, Call 1 gets invalidResultReference.
        let req_create = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Email/set", {"accountId": mb, "update": {e.a.inbox_only.to_string(): {"keywords": {"$seen": true}}}}, "c0"],
            ["Email/set", {"accountId": mb, "#create": {"resultOf": "c0", "name": "Email/set", "path": "/created"}}, "c1"]
        ]
    })
    .to_string();
        let (status, body_a, hit) = e.post(&token, &req_create).await;
        assert_eq!((status, hit), (200, false));
        assert!(e.is_read(e.a.inbox_only).await);
        let doc_a: Value = serde_json::from_str(&body_a).unwrap();
        assert_eq!(doc_a["methodResponses"][0][0], "Email/set");
        assert_eq!(doc_a["methodResponses"][1][0], "error");
        assert_eq!(
            doc_a["methodResponses"][1][1]["type"],
            "urn:ietf:params:jmap:error:invalidResultReference"
        );
        e.owner
            .execute(
                "UPDATE messages SET is_read = FALSE WHERE id = $1 AND mailbox_id = $2",
                &[&e.a.inbox_only, &e.a.mailbox],
            )
            .await
            .unwrap();

        // Case A2 (#356 Wave 3): Email/set followed by EmailSubmission/set with #create ref
        // runs NATIVELY without deferring to Go: Call 0 marks read, Call 1 gets invalidResultReference.
        let req_sub_ref = json!({
            "using": ["urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
            "methodCalls": [
                ["Email/set", {"accountId": mb, "update": {e.a.inbox_only.to_string(): {"keywords": {"$seen": true}}}}, "c0"],
                ["EmailSubmission/set", {"accountId": mb, "#create": {"resultOf": "c0", "name": "Email/set", "path": "/created"}}, "c1"]
            ]
        })
        .to_string();
        let (status, body_a2, hit) = e.post(&token, &req_sub_ref).await;
        assert_eq!((status, hit), (200, false));
        assert!(e.is_read(e.a.inbox_only).await);
        let doc_a2: Value = serde_json::from_str(&body_a2).unwrap();
        assert_eq!(doc_a2["methodResponses"][0][0], "Email/set");
        assert_eq!(doc_a2["methodResponses"][1][0], "error");
        assert_eq!(
            doc_a2["methodResponses"][1][1]["type"],
            "urn:ietf:params:jmap:error:invalidResultReference"
        );
        e.owner
            .execute(
                "UPDATE messages SET is_read = FALSE WHERE id = $1 AND mailbox_id = $2",
                &[&e.a.inbox_only, &e.a.mailbox],
            )
            .await
            .unwrap();

        // Case B (#328 Wave 2b): Email/set followed by EmailSubmission/set targeting message with
        // has_attachments=true runs NATIVELY without deferring to Go.
        e.owner
            .execute(
                "UPDATE messages SET has_attachments = TRUE WHERE id = $1 AND mailbox_id = $2",
                &[&e.a.two_labels, &e.a.mailbox],
            )
            .await
            .unwrap();
        let req_attach = json!({
        "using": ["urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
        "methodCalls": [
            ["Email/set", {"accountId": mb, "update": {e.a.inbox_only.to_string(): {"keywords": {"$seen": true}}}}, "c0"],
            ["EmailSubmission/set", {"accountId": mb, "create": {"s1": {"emailId": e.a.two_labels.to_string()}}}, "c1"]
        ]
    })
    .to_string();
        let (status, _, hit) = e.post(&token, &req_attach).await;
        assert_eq!((status, hit), (200, false));
        assert!(e.is_read(e.a.inbox_only).await);

        // Reset inbox_only $seen, then Case C (#328 Wave 2b): Email/set followed by Email/get (#ids)
        // in mailbox with smime-encrypted message runs NATIVELY and returns decryptState='no_key'.
        e.owner
            .execute(
                "UPDATE messages SET is_read = FALSE WHERE id = $1 AND mailbox_id = $2",
                &[&e.a.inbox_only, &e.a.mailbox],
            )
            .await
            .unwrap();
        let audit_before_c = e.audit_rows(e.a.mailbox).await;
        e.owner
        .execute(
            "UPDATE messages SET crypto_type = 'smime-encrypted' WHERE id = $1 AND mailbox_id = $2",
            &[&e.a.two_labels, &e.a.mailbox],
        )
        .await
        .unwrap();
        let req_enc_ref = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Email/set", {"accountId": mb, "update": {e.a.inbox_only.to_string(): {"keywords": {"$seen": true}}}}, "c0"],
            ["Email/query", {"accountId": mb, "filter": {"inMailbox": e.a.inbox.to_string()}}, "q0"],
            ["Email/get", {"accountId": mb, "#ids": {"resultOf": "q0", "name": "Email/query", "path": "/ids"}}, "g0"]
        ]
    })
    .to_string();
        let (status, body_c, hit) = e.post(&token, &req_enc_ref).await;
        assert_eq!((status, hit), (200, false));
        assert!(e.is_read(e.a.inbox_only).await);
        assert!(e.audit_rows(e.a.mailbox).await > audit_before_c);
        let doc_c: Value = serde_json::from_str(&body_c).unwrap();
        let list_c = doc_c["methodResponses"][2][1]["list"].as_array().unwrap();
        let enc_entry = list_c
            .iter()
            .find(|item| item["id"] == e.a.two_labels.to_string())
            .expect("encrypted email present in Email/get");
        assert_eq!(enc_entry["decryptState"], "no_key");
    }
);

wave1_case!(non_family_delegated_matrix_under_force_rls, |e| {
    let delegate_token = e.token(e.a.user);
    let target_mb = e.b.mailbox.to_string();

    // Helper closures for method calls.
    let call = |using: &[&str], method: &str, args: Value| {
        json!({"using": using, "methodCalls": [[method, args, "c0"]]}).to_string()
    };

    // 1. No grant -> accountNotFound.
    let (_, body, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:mail"],
                "Email/get",
                json!({"accountId": target_mb, "ids": [e.b.inbox_only.to_string()]}),
            ),
        )
        .await;
    assert!(!hit);
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["methodResponses"][0][0], "error");
    assert_eq!(
        doc["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:accountNotFound"
    );

    // 2. Grant = "read": read methods work on target_mb; mutators, submissions & Identity/set return forbidden (500).
    e.grant(e.b.mailbox, e.a.user, e.b.user, "read").await;

    for (using, method, args) in [
        (
            vec!["urn:ietf:params:jmap:mail"],
            "Email/get",
            json!({"accountId": target_mb, "ids": [e.b.inbox_only.to_string()]}),
        ),
        (
            vec!["urn:ietf:params:jmap:mail"],
            "Email/query",
            json!({"accountId": target_mb, "filter": {"inMailbox": e.b.inbox.to_string()}}),
        ),
        (
            vec!["urn:ietf:params:jmap:mail"],
            "Email/changes",
            json!({"accountId": target_mb, "sinceState": "0"}),
        ),
        (
            vec!["urn:ietf:params:jmap:mail"],
            "Mailbox/get",
            json!({"accountId": target_mb}),
        ),
        (
            vec!["urn:ietf:params:jmap:mail"],
            "Email/deletedQuery",
            json!({"accountId": target_mb}),
        ),
    ] {
        let (status, body, hit) = e.post(&delegate_token, &call(&using, method, args)).await;
        assert_eq!((status, hit), (200, false), "read perm on {method}");
        let doc: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["methodResponses"][0][0], method, "{body}");
    }

    // Verify audit actor_user_id = delegate (a.user) and mailbox_id = target (b.mailbox).
    let audit_actor: i64 = e
        .owner
        .query_one(
            "SELECT actor_user_id FROM mailbox_audit_log WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1",
            &[&e.b.mailbox],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audit_actor, e.a.user);

    for (using, method, args) in [
        (
            vec!["urn:ietf:params:jmap:mail"],
            "Email/set",
            json!({"accountId": target_mb, "update": {e.b.inbox_only.to_string(): {"keywords": {"$seen": true}}}}),
        ),
        (
            vec!["urn:ietf:params:jmap:mail"],
            "Mailbox/set",
            json!({"accountId": target_mb, "create": {"m1": {"name": "Blocked"}}}),
        ),
        (
            vec!["urn:ietf:params:jmap:submission"],
            "EmailSubmission/get",
            json!({"accountId": target_mb}),
        ),
        (
            vec!["urn:ietf:params:jmap:submission"],
            "EmailSubmission/set",
            json!({"accountId": target_mb, "create": {"s1": {"emailId": e.b.inbox_only.to_string()}}}),
        ),
        (
            vec!["urn:ietf:params:jmap:submission"],
            "Identity/set",
            json!({"accountId": target_mb, "create": {"i1": {"name": "x"}}}),
        ),
    ] {
        let (status, body, hit) = e.post(&delegate_token, &call(&using, method, args)).await;
        assert_eq!((status, hit), (200, false), "read perm blocks {method}");
        let doc: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["methodResponses"][0][0], "error", "{method}: {body}");
        assert_eq!(
            doc["methodResponses"][0][1]["type"],
            "urn:ietf:params:jmap:error:forbidden"
        );
        assert_eq!(doc["methodResponses"][0][1]["status"], 500);
    }
    assert!(!e.is_read(e.b.inbox_only).await);

    // 3. Grant = "send_on_behalf": EmailSubmission/* admitted, Email/set & Identity/set still forbidden.
    e.grant(e.b.mailbox, e.a.user, e.b.user, "send_on_behalf")
        .await;
    let (status, body, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:submission"],
                "EmailSubmission/get",
                json!({"accountId": target_mb}),
            ),
        )
        .await;
    assert_eq!((status, hit), (200, false));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][0],
        "EmailSubmission/get"
    );

    let (status, body, hit) = e
        .post(
            &delegate_token,
            &call(&["urn:ietf:params:jmap:submission"], "EmailSubmission/set", json!({"accountId": target_mb, "create": {"s1": {"emailId": e.b.inbox_only.to_string()}}})),
        )
        .await;
    assert_eq!((status, hit), (200, false));
    let sub_doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        sub_doc["methodResponses"][0][0], "EmailSubmission/set",
        "{body}"
    );

    let (_, body, hit) = e
        .post(
            &delegate_token,
            &call(&["urn:ietf:params:jmap:mail"], "Email/set", json!({"accountId": target_mb, "update": {e.b.inbox_only.to_string(): {"keywords": {"$seen": true}}}})),
        )
        .await;
    assert!(!hit);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:forbidden"
    );

    // 4. Grant = "full_access": Email/set succeeds, Identity/set STILL forbidden (Gate::Personal).
    e.grant(e.b.mailbox, e.a.user, e.b.user, "full_access")
        .await;
    let (status, body, hit) = e
        .post(
            &delegate_token,
            &call(&["urn:ietf:params:jmap:mail"], "Email/set", json!({"accountId": target_mb, "update": {e.b.inbox_only.to_string(): {"keywords": {"$seen": true}}}})),
        )
        .await;
    assert_eq!((status, hit), (200, false));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][0],
        "Email/set"
    );
    assert!(e.is_read(e.b.inbox_only).await);

    let (_, body, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:submission"],
                "Identity/set",
                json!({"accountId": target_mb, "create": {"i1": {"name": "x"}}}),
            ),
        )
        .await;
    assert!(!hit);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:forbidden"
    );

    // 5. Personal Gate methods without parseAccountID (Identity/get, Core/echo) & disabled Email/recoveryReceipt.
    let (status, body, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:submission"],
                "Identity/get",
                json!({"accountId": target_mb}),
            ),
        )
        .await;
    assert_eq!((status, hit), (200, false));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][0],
        "Identity/get"
    );

    let (status, body, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:mail"],
                "Email/recoveryReceipt",
                json!({"accountId": "not-an-id", "ids": ["1"]}),
            ),
        )
        .await;
    assert_eq!((status, hit), (200, false));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:forbidden"
    );

    // 6. Delegated Email/get on smime-encrypted message executes natively under target_auth,
    // using the delegate's ($actor) keystore -> no_key (never borrows target owner's keys).
    e.owner
        .execute(
            "UPDATE messages SET crypto_type = 'smime-encrypted' WHERE id = $1 AND mailbox_id = $2",
            &[&e.b.two_labels, &e.b.mailbox],
        )
        .await
        .unwrap();
    let (status, body6, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:mail"],
                "Email/get",
                json!({"accountId": target_mb, "ids": [e.b.two_labels.to_string()]}),
            ),
        )
        .await;
    assert_eq!((status, hit), (200, false));
    let doc6: Value = serde_json::from_str(&body6).unwrap();
    assert_eq!(
        doc6["methodResponses"][0][1]["list"][0]["decryptState"],
        "no_key"
    );

    // 7. Suspended target mailbox -> forbidden (500).
    e.set_suspended(e.b.mailbox, true).await;
    let (_, body, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:mail"],
                "Mailbox/get",
                json!({"accountId": target_mb}),
            ),
        )
        .await;
    assert!(!hit);
    let susp_doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        susp_doc["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:forbidden"
    );
    assert_eq!(susp_doc["methodResponses"][0][1]["status"], 500);
    e.set_suspended(e.b.mailbox, false).await;

    // 8. Revoked grant -> accountNotFound.
    e.revoke(e.b.mailbox, e.a.user).await;
    let (_, body, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:mail"],
                "Mailbox/get",
                json!({"accountId": target_mb}),
            ),
        )
        .await;
    assert!(!hit);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:accountNotFound"
    );
});

fn parse_op_hex(hex: &str) -> setjoin_contracts::ids::OperationId {
    assert_eq!(hex.len(), 32, "operation hex length");
    let mut bytes = [0u8; 16];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex byte");
    }
    setjoin_contracts::ids::OperationId(bytes)
}

wave1_case!(wave2a_email_set_multiphase_and_ownership_gate, |e| {
    let token = e.token(e.a.user);
    let mb = e.a.mailbox.to_string();
    let inbox_tag = e.a.inbox.to_string();
    let tx_factory = setjoin_gateway::policy_composition::tx_factory_from_executors(&e.exec, None)
        .expect("app pool");
    let principal = tx_factory
        .mint_capability_primary_mailbox(
            setjoin_contracts::ids::ActorId::new(e.a.user).unwrap(),
            "",
            "127.0.0.1",
        )
        .await
        .unwrap();
    let read_cap = principal.require_read().unwrap();

    // Seed an owned blob (via blob_user_charges for user A) and a foreign blob (user B).
    let own_sha = "a1".repeat(32);
    let foreign_sha = "b2".repeat(32);
    for (sha, user) in [(&own_sha, e.a.user), (&foreign_sha, e.b.user)] {
        e.owner
            .query_typed(
                "INSERT INTO blobs(sha256, minio_ref, size_bytes, content_type) \
                 VALUES ($1, $1, 5, 'text/plain') ON CONFLICT DO NOTHING",
                &[(&sha, Type::TEXT)],
            )
            .await
            .unwrap();
        e.owner
            .query_typed(
                "INSERT INTO blob_user_charges(blob_sha256, user_id, size_bytes) \
                 VALUES ($1, $2, 5) ON CONFLICT (blob_sha256) DO UPDATE SET user_id = EXCLUDED.user_id",
                &[(&sha, Type::TEXT), (&user, Type::INT8)],
            )
            .await
            .unwrap();
    }

    // 1. Create with owned + foreign attachments -> owned succeeds + createdIds, foreign forbidden.
    let audit0 = e.audit_rows(e.a.mailbox).await;
    let create_req = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            {
                "accountId": mb,
                "ifInState": "0",
                "create": {
                    "c_own": {
                        "mailboxIds": { inbox_tag.clone(): true },
                        "subject": "Owned attach",
                        "bodyValues": { "text": { "value": "hi" } },
                        "attachments": [{ "blobId": own_sha, "type": "text/plain", "size": 5 }]
                    },
                    "c_foreign": {
                        "mailboxIds": { inbox_tag.clone(): true },
                        "subject": "Foreign attach",
                        "bodyValues": { "text": { "value": "no" } },
                        "attachments": [{ "blobId": foreign_sha, "type": "text/plain", "size": 5 }]
                    }
                }
            },
            "c0"
        ]]
    })
    .to_string();
    let (status, body, hit) = e.post(&token, &create_req).await;
    assert_eq!((status, hit), (200, false));
    let doc: Value = serde_json::from_str(&body).unwrap();
    let res = &doc["methodResponses"][0][1];
    assert!(res["created"]["c_own"]["id"].as_str().is_some(), "{doc}");
    assert_eq!(res["notCreated"]["c_foreign"]["type"], "forbidden", "{doc}");
    assert!(doc["createdIds"]["c_own"].is_string(), "{doc}");
    assert_eq!(e.audit_rows(e.a.mailbox).await, audit0 + 1);

    // 2. All-stripped create STILL executes jmap_email_set_create("{}") and writes audit row.
    let all_denied_req = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            {
                "accountId": mb,
                "create": {
                    "c_bad": {
                        "mailboxIds": { inbox_tag.clone(): true },
                        "subject": "Denied",
                        "attachments": [{ "blobId": foreign_sha }]
                    }
                }
            },
            "c0"
        ]]
    })
    .to_string();
    let (status, body, hit) = e.post(&token, &all_denied_req).await;
    assert_eq!((status, hit), (200, false));
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        doc["methodResponses"][0][1]["notCreated"]["c_bad"]["type"], "forbidden",
        "{doc}"
    );
    assert!(
        doc["methodResponses"][0][1]["newState"].is_string(),
        "{doc}"
    );
    assert_eq!(e.audit_rows(e.a.mailbox).await, audit0 + 2);

    // 3. Q1 updated shapes:
    // 3a. Pure ordinary update -> updated array.
    let pure_ord_req = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            {
                "accountId": mb,
                "update": { e.a.inbox_only.to_string(): { "keywords": { "$flagged": true } } }
            },
            "c0"
        ]]
    })
    .to_string();
    let (status, body, hit) = e.post(&token, &pure_ord_req).await;
    assert_eq!((status, hit), (200, false));
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert!(doc["methodResponses"][0][1]["updated"].is_array(), "{doc}");

    // 3b. Ordinary + all-failed snooze -> updated remains array + notUpdated has failed snooze.
    let future = (chrono::Utc::now() + chrono::Duration::hours(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let ord_plus_bad_snooze = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            {
                "accountId": mb,
                "update": {
                    e.a.inbox_only.to_string(): { "keywords": { "$flagged": false } },
                    "not-an-id": { "snoozeUntil": future }
                }
            },
            "c0"
        ]]
    })
    .to_string();
    let (status, body, hit) = e.post(&token, &ord_plus_bad_snooze).await;
    assert_eq!((status, hit), (200, false));
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert!(doc["methodResponses"][0][1]["updated"].is_array(), "{doc}");
    assert_eq!(
        doc["methodResponses"][0][1]["notUpdated"]["not-an-id"]["type"], "invalidArguments",
        "{doc}"
    );

    // 3c. Pure snooze -> updated object {"<id>": null}.
    let pure_snooze = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            {
                "accountId": mb,
                "update": { e.a.two_labels.to_string(): { "snoozeUntil": future } }
            },
            "c0"
        ]]
    })
    .to_string();
    let (status, body, hit) = e.post(&token, &pure_snooze).await;
    assert_eq!((status, hit), (200, false));
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        doc["methodResponses"][0][1]["updated"],
        json!({ e.a.two_labels.to_string(): Value::Null }),
        "{doc}"
    );

    // 3d. Mixed ordinary + successful snooze -> RFC 8620 object preserving both IDs.
    let mixed_ord_snooze = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            {
                "accountId": mb,
                "update": {
                    e.a.inbox_only.to_string(): { "keywords": { "$flagged": true } },
                    e.a.two_labels.to_string(): { "snoozeUntil": future }
                }
            },
            "c0"
        ]]
    })
    .to_string();
    let (status, body, hit) = e.post(&token, &mixed_ord_snooze).await;
    assert_eq!((status, hit), (200, false));
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        doc["methodResponses"][0][1]["updated"],
        json!({
            e.a.inbox_only.to_string(): Value::Null,
            e.a.two_labels.to_string(): Value::Null,
        }),
        "{doc}"
    );

    // 4. Mixed create + update + destroy (with malformed destroy ID) in one locked tx.
    let created_id = res["created"]["c_own"]["id"].as_str().unwrap().to_owned();
    let audit_before_mixed = e.audit_rows(e.a.mailbox).await;
    let mixed_cud = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            {
                "accountId": mb,
                "create": {
                    "c2": {
                        "mailboxIds": { inbox_tag: true },
                        "subject": "Batch C2",
                        "bodyValues": { "text": { "value": "c2" } }
                    }
                },
                "update": { e.a.inbox_only.to_string(): { "keywords": { "$flagged": false } } },
                "destroy": [created_id, "bad-destroy"]
            },
            "c0"
        ]]
    })
    .to_string();
    let (status, body, hit) = e.post(&token, &mixed_cud).await;
    assert_eq!((status, hit), (200, false));
    let doc: Value = serde_json::from_str(&body).unwrap();
    let mres = &doc["methodResponses"][0][1];
    assert!(mres["created"]["c2"]["id"].is_string(), "{doc}");
    assert!(mres["updated"].is_array(), "{doc}");
    assert_eq!(
        mres["notDestroyed"]["bad-destroy"]["type"], "notFound",
        "{doc}"
    );
    assert_eq!(e.audit_rows(e.a.mailbox).await, audit_before_mixed + 1);

    // 5. Zero-phase {accountId} and destroy: [] both record email_set audit rows with operation,
    // and lookup_set_seen recovers Committed for them.
    let audit_before_zero = e.audit_rows(e.a.mailbox).await;
    for req_body in [
        json!({"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":mb},"c0"]]}).to_string(),
        json!({"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":mb,"destroy":[]},"c0"]]}).to_string(),
    ] {
        let (status, _, hit) = e.post(&token, &req_body).await;
        assert_eq!((status, hit), (200, false));
    }
    assert_eq!(e.audit_rows(e.a.mailbox).await, audit_before_zero + 2);
    let op_rows = e
        .owner
        .query_typed(
            "SELECT details->>'operation' FROM mailbox_audit_log \
             WHERE mailbox_id = $1 AND action = 'email_set' AND details ? 'operation' \
             ORDER BY id DESC LIMIT 3",
            &[(&e.a.mailbox, Type::INT8)],
        )
        .await
        .unwrap();
    assert_eq!(op_rows.len(), 3);
    for row in op_rows {
        let op = parse_op_hex(row.get::<_, &str>(0));
        let found = setjoin_jmap::lookup_set_seen(&tx_factory, &read_cap, op)
            .await
            .unwrap();
        assert_eq!(found, setjoin_jmap::OperationLookup::Committed);
    }

    // Cleanup test-only rows created in this test.
    let _ = e
        .owner
        .query_typed(
            "DELETE FROM scheduled_actions WHERE mailbox_id = $1",
            &[(&e.a.mailbox, Type::INT8)],
        )
        .await;
    let _ = e
        .owner
        .execute(
            "DELETE FROM blobs WHERE sha256 = ANY($1)",
            &[&vec![own_sha, foreign_sha]],
        )
        .await;
});

wave1_case!(wave2a_email_recovery_receipt_end_to_end, |e| {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;

    // 1. Feature toggle OFF -> forbidden before arg decode.
    let token = e.token(e.a.user);
    let req_invalid = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/recoveryReceipt", {"accountId": "not-an-id", "ids": []}, "r0"]]
    })
    .to_string();
    let (status, body, hit) = e.post(&token, &req_invalid).await;
    assert_eq!((status, hit), (200, false));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:forbidden"
    );

    // 2. Toggle ON without continuity_signer/continuity_boot -> still forbidden.
    e.owner
        .execute(
            "UPDATE feature_toggles SET enabled = TRUE WHERE key = 'feature.client_recovery_receipts'",
            &[],
        )
        .await
        .unwrap();
    let (status, body, hit) = e.post(&token, &req_invalid).await;
    assert_eq!((status, hit), (200, false));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:forbidden"
    );

    // 3. Spin up local JmapCommands with ContinuitySigner + fake streaming S3 backend.
    let objects: Arc<std::sync::Mutex<BTreeMap<String, Vec<u8>>>> =
        Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    let s3_state = objects.clone();
    let s3_addr = common::fake_upstream(move |req| {
        let s3_state = s3_state.clone();
        async move {
            if req.uri().query() == Some("location=") {
                return hyper::Response::builder()
                    .header("content-type", "application/xml")
                    .body(full("<LocationConstraint>us-east-1</LocationConstraint>"))
                    .unwrap();
            }
            let key = req
                .uri()
                .path()
                .strip_prefix("/mailblobs/")
                .unwrap_or(req.uri().path());
            let map = s3_state.lock().unwrap();
            match map.get(key) {
                Some(bytes) => hyper::Response::builder()
                    .status(200)
                    .header("content-length", bytes.len().to_string())
                    .body(full(bytes.clone()))
                    .unwrap(),
                None => hyper::Response::builder()
                    .status(404)
                    .body(full("NoSuchKey"))
                    .unwrap(),
            }
        }
    })
    .await;

    let boot = "bba31885-d8f1-4c47-8753-56bf86e59807";
    let seed = [0x42u8; 32];
    let signer = Arc::new(setjoin_gateway::jmap::family::ContinuitySigner::new(
        "cont-k1".to_owned(),
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap(),
    ));
    let doc = json!({ "keys": [jwk(KID, &public(&e.key))] })
        .to_string()
        .into_bytes();
    let jwks = Arc::new(Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    })));
    let exec = ScopedExecutor::from_dsn(e.app_dsn.as_deref().unwrap_or(&e.dsn), 4).unwrap();
    let worker = ScopedExecutor::from_dsn(&e.dsn, 2).unwrap();
    let mut services = JmapServices::new(worker.clone(), "mail.test".into(), 64);
    services.continuity_boot = Some(boot.to_owned());
    services.continuity_signer = Some(signer.clone());
    services.store = Some(Arc::new(
        setjoin_gateway::recovery_worker::S3Store::new(
            &format!("http://{s3_addr}"),
            "mailblobs",
            "test-access",
            "test-secret",
        )
        .unwrap(),
    ));
    let route = JmapRoute(Arc::new(JmapCommands {
        services: Some(Arc::new(services)),
        exec,
        worker: Some(worker),
        denylist: None,
        keys: jwks,
        issuer: "mailserver".into(),
    }));
    let unused_upstream = common::fake_upstream(|_| async {
        hyper::Response::builder()
            .status(299)
            .body(full("unused"))
            .unwrap()
    })
    .await;
    let gw = common::gateway(unused_upstream, "", RouteTable::proxy_all().with(route)).await;

    let call_receipt = |args: Value| {
        let token = token.clone();
        async move {
            let body = json!({
                "using": ["urn:ietf:params:jmap:mail"],
                "methodCalls": [["Email/recoveryReceipt", args, "r0"]]
            })
            .to_string();
            let req = Request::post("/jmap")
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(full(body))
                .unwrap();
            let resp = common::send(gw, req).await;
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let doc: Value = serde_json::from_slice(&bytes).unwrap();
            (status, doc)
        }
    };

    // Seed S3 raw MIME + attachment for e.a.inbox_only.
    let raw_mime = b"From: alice@test\r\nSubject: Receipt\r\n\r\nRecoverable body\r\n";
    let raw_sha: String = Sha256::digest(raw_mime)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let att_bytes = b"attachment-data";
    let att_sha: String = Sha256::digest(att_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let raw_ref_key: String = e
        .owner
        .query_typed(
            "SELECT raw_ref FROM messages WHERE id = $1 AND mailbox_id = $2",
            &[(&e.a.inbox_only, Type::INT8), (&e.a.mailbox, Type::INT8)],
        )
        .await
        .unwrap()[0]
        .get(0);
    {
        let mut map = objects.lock().unwrap();
        if !raw_ref_key.contains('\n') {
            map.insert(raw_ref_key.clone(), raw_mime.to_vec());
        }
        map.insert(att_sha.clone(), att_bytes.to_vec());
    }
    e.owner
        .query_typed(
            "INSERT INTO blobs(sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $1, $2, 'application/octet-stream') ON CONFLICT DO NOTHING",
            &[
                (&att_sha, Type::TEXT),
                (&(att_bytes.len() as i64), Type::INT8),
            ],
        )
        .await
        .unwrap();
    e.owner
        .query_typed(
            "INSERT INTO message_attachments(message_id, received_at, blob_sha256, filename, content_type, disposition, size_bytes) \
             SELECT id, received_at, $2, 'doc.bin', 'application/octet-stream', 'attachment', $3 \
             FROM messages WHERE id = $1 AND mailbox_id = $4",
            &[
                (&e.a.inbox_only, Type::INT8),
                (&att_sha, Type::TEXT),
                (&(att_bytes.len() as i64), Type::INT8),
                (&e.a.mailbox, Type::INT8),
            ],
        )
        .await
        .unwrap();

    // 3a. Invalid args (unknown field, empty ids, bad msg id).
    let (status, doc) = call_receipt(json!({"accountId": e.a.mailbox.to_string(), "ids": [e.a.inbox_only.to_string()], "extra": 1})).await;
    assert_eq!(status, 200);
    assert_eq!(
        doc["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:invalidArguments"
    );
    let (_, doc) = call_receipt(json!({"accountId": e.a.mailbox.to_string(), "ids": ["0"]})).await;
    assert_eq!(
        doc["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:invalidArguments"
    );

    // 3b. Enabled success + cross-tenant duplicate preserved in notFound + signature verify.
    let mb_str = e.a.mailbox.to_string();
    let msg_str = e.a.inbox_only.to_string();
    let foreign_str = e.b.inbox_only.to_string();
    let (status, doc) = call_receipt(json!({
        "accountId": mb_str,
        "ids": [foreign_str, msg_str, foreign_str, "999999999"]
    }))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        doc["methodResponses"][0][0], "Email/recoveryReceipt",
        "{doc}"
    );
    let res = &doc["methodResponses"][0][1];
    assert_eq!(
        res["notFound"],
        json!([foreign_str, foreign_str, "999999999"]),
        "{doc}"
    );
    let item = &res["list"][0];
    assert_eq!(item["id"], msg_str);
    let claims = &item["receipt"]["claims"];
    assert_eq!(claims["v"], 1);
    assert_eq!(claims["bootEpoch"], boot);
    assert_eq!(claims["keyId"], "cont-k1");
    if !raw_ref_key.contains('\n') {
        assert_eq!(claims["rawMimeSha256"], raw_sha);
    }
    let expected_identity_input = format!(
        "v1\0{}\0{}\0{}\0{}",
        claims["installationId"].as_str().unwrap(),
        claims["accountId"].as_str().unwrap(),
        claims["originalMessageId"].as_str().unwrap(),
        claims["rawMimeSha256"].as_str().unwrap(),
    );
    let expected_identity: String = Sha256::digest(expected_identity_input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(item["artifactIdentity"], expected_identity);

    #[derive(serde::Serialize)]
    struct WireBlob<'a> {
        #[serde(rename = "blobId")]
        blob_id: &'a str,
        sha256: &'a str,
        size: &'a str,
    }
    #[derive(serde::Serialize)]
    struct WireClaims<'a> {
        v: i64,
        #[serde(rename = "installationId")]
        installation_id: &'a str,
        #[serde(rename = "accountId")]
        account_id: &'a str,
        #[serde(rename = "originalMessageId")]
        original_message_id: &'a str,
        eligibility: &'a str,
        #[serde(rename = "rawMimeSha256")]
        raw_mime_sha256: &'a str,
        #[serde(rename = "rawMimeSize")]
        raw_mime_size: &'a str,
        blobs: Option<Vec<WireBlob<'a>>>,
        #[serde(rename = "timelineGeneration")]
        timeline_generation: &'a str,
        #[serde(rename = "stateWatermark")]
        state_watermark: &'a str,
        #[serde(rename = "bootEpoch")]
        boot_epoch: &'a str,
        #[serde(rename = "issuedAt")]
        issued_at: &'a str,
        #[serde(rename = "keyId")]
        key_id: &'a str,
    }
    let wire_blobs: Vec<WireBlob<'_>> = claims["blobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| WireBlob {
            blob_id: b["blobId"].as_str().unwrap(),
            sha256: b["sha256"].as_str().unwrap(),
            size: b["size"].as_str().unwrap(),
        })
        .collect();
    let wire_claims = WireClaims {
        v: claims["v"].as_i64().unwrap(),
        installation_id: claims["installationId"].as_str().unwrap(),
        account_id: claims["accountId"].as_str().unwrap(),
        original_message_id: claims["originalMessageId"].as_str().unwrap(),
        eligibility: claims["eligibility"].as_str().unwrap(),
        raw_mime_sha256: claims["rawMimeSha256"].as_str().unwrap(),
        raw_mime_size: claims["rawMimeSize"].as_str().unwrap(),
        blobs: (!wire_blobs.is_empty()).then_some(wire_blobs),
        timeline_generation: claims["timelineGeneration"].as_str().unwrap(),
        state_watermark: claims["stateWatermark"].as_str().unwrap(),
        boot_epoch: claims["bootEpoch"].as_str().unwrap(),
        issued_at: claims["issuedAt"].as_str().unwrap(),
        key_id: claims["keyId"].as_str().unwrap(),
    };
    let canonical =
        setjoin_gateway::jmap::reply::go_compact(&serde_json::to_string(&wire_claims).unwrap())
            .unwrap();
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(item["receipt"]["signature"].as_str().unwrap())
        .unwrap();
    assert!(signer.verify(canonical.as_bytes(), &sig_bytes));

    // Attachment-free receipt verifies canonical `"blobs": null` signature while preserving wire `"blobs": []`.
    let two_raw_ref: String = e
        .owner
        .query_typed(
            "SELECT raw_ref FROM messages WHERE id = $1 AND mailbox_id = $2",
            &[(&e.a.two_labels, Type::INT8), (&e.a.mailbox, Type::INT8)],
        )
        .await
        .unwrap()[0]
        .get(0);
    let two_mime = b"From: bob@test\r\nSubject: NoAttach\r\n\r\nPlain body\r\n";
    let two_sha: String = Sha256::digest(two_mime)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if !two_raw_ref.contains('\n') {
        objects
            .lock()
            .unwrap()
            .insert(two_raw_ref.clone(), two_mime.to_vec());
    }
    let two_str = e.a.two_labels.to_string();
    let (status, empty_doc) = call_receipt(json!({
        "accountId": mb_str,
        "ids": [two_str]
    }))
    .await;
    assert_eq!(status, 200);
    let empty_item = &empty_doc["methodResponses"][0][1]["list"][0];
    let empty_claims = &empty_item["receipt"]["claims"];
    assert_eq!(empty_claims["blobs"], json!([]));
    if !two_raw_ref.contains('\n') {
        assert_eq!(empty_claims["rawMimeSha256"], two_sha);
    }
    let empty_wire_claims = WireClaims {
        v: empty_claims["v"].as_i64().unwrap(),
        installation_id: empty_claims["installationId"].as_str().unwrap(),
        account_id: empty_claims["accountId"].as_str().unwrap(),
        original_message_id: empty_claims["originalMessageId"].as_str().unwrap(),
        eligibility: empty_claims["eligibility"].as_str().unwrap(),
        raw_mime_sha256: empty_claims["rawMimeSha256"].as_str().unwrap(),
        raw_mime_size: empty_claims["rawMimeSize"].as_str().unwrap(),
        blobs: None,
        timeline_generation: empty_claims["timelineGeneration"].as_str().unwrap(),
        state_watermark: empty_claims["stateWatermark"].as_str().unwrap(),
        boot_epoch: empty_claims["bootEpoch"].as_str().unwrap(),
        issued_at: empty_claims["issuedAt"].as_str().unwrap(),
        key_id: empty_claims["keyId"].as_str().unwrap(),
    };
    let empty_canonical = setjoin_gateway::jmap::reply::go_compact(
        &serde_json::to_string(&empty_wire_claims).unwrap(),
    )
    .unwrap();
    let empty_sig = URL_SAFE_NO_PAD
        .decode(empty_item["receipt"]["signature"].as_str().unwrap())
        .unwrap();
    assert!(signer.verify(empty_canonical.as_bytes(), &empty_sig));

    // 3c. Corrupt / truncated S3 blob -> serverFail.
    objects
        .lock()
        .unwrap()
        .insert(att_sha.clone(), b"short".to_vec());
    let (_, doc) = call_receipt(json!({"accountId": mb_str, "ids": [msg_str]})).await;
    assert_eq!(
        doc["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:serverFail"
    );

    // 3d. Oversized S3 blob (> max_upload 64 bytes) -> aborted & serverFail.
    objects
        .lock()
        .unwrap()
        .insert(att_sha.clone(), vec![b'x'; 128]);
    let (_, doc) = call_receipt(json!({"accountId": mb_str, "ids": [msg_str]})).await;
    assert_eq!(
        doc["methodResponses"][0][1]["type"],
        "urn:ietf:params:jmap:error:serverFail"
    );

    // Cleanup test-only attachment & blob rows.
    let _ = e
        .owner
        .query_typed(
            "DELETE FROM message_attachments WHERE message_id = $1 AND blob_sha256 = $2",
            &[(&e.a.inbox_only, Type::INT8), (&att_sha, Type::TEXT)],
        )
        .await;
    let _ = e
        .owner
        .query_typed(
            "DELETE FROM blobs WHERE sha256 = $1",
            &[(&att_sha, Type::TEXT)],
        )
        .await;
});

wave1_case!(wave2b_smime_attachments_and_decrypt_on_read, |e| {
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;

    const ENC_KEY: &str = "wave2b-smime-audit-key-32-bytes!";

    let objects: Arc<std::sync::Mutex<BTreeMap<String, Vec<u8>>>> =
        Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    let s3_state = objects.clone();
    let s3_addr = common::fake_upstream(move |req| {
        let s3_state = s3_state.clone();
        async move {
            if req.uri().query() == Some("location=") {
                return hyper::Response::builder()
                    .header("content-type", "application/xml")
                    .body(full("<LocationConstraint>us-east-1</LocationConstraint>"))
                    .unwrap();
            }
            let key = req
                .uri()
                .path()
                .strip_prefix("/mailblobs/")
                .unwrap_or(req.uri().path())
                .to_owned();
            if *req.method() == hyper::Method::PUT {
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                s3_state.lock().unwrap().insert(key, bytes.to_vec());
                return hyper::Response::builder()
                    .status(200)
                    .body(full(""))
                    .unwrap();
            }
            let map = s3_state.lock().unwrap();
            match map.get(&key) {
                Some(bytes) => hyper::Response::builder()
                    .status(200)
                    .header("content-length", bytes.len().to_string())
                    .body(full(bytes.clone()))
                    .unwrap(),
                None => hyper::Response::builder()
                    .status(404)
                    .body(full("NoSuchKey"))
                    .unwrap(),
            }
        }
    })
    .await;

    let doc = json!({ "keys": [jwk(KID, &public(&e.key))] })
        .to_string()
        .into_bytes();
    let jwks = Arc::new(Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    })));
    let exec = ScopedExecutor::from_dsn(e.app_dsn.as_deref().unwrap_or(&e.dsn), 4).unwrap();
    // Pool size 1 forces connection reuse across actor transitions, verifying
    // transaction-local AUDIT_SCOPE and actor-scoped key isolation.
    let worker_dsn = std::env::var("DB_WORKER_DSN").unwrap_or_else(|_| e.dsn.clone());
    let worker = ScopedExecutor::from_dsn(&worker_dsn, 1)
        .unwrap()
        .with_audit_keys(ENC_KEY.into(), String::new());
    let store = Arc::new(
        setjoin_gateway::recovery_worker::S3Store::new(
            &format!("http://{s3_addr}"),
            "mailblobs",
            "test-access",
            "test-secret",
        )
        .unwrap(),
    );

    let mut services_no_store = JmapServices::new(worker.clone(), "mail.test".into(), 52_428_800);
    services_no_store.store = None;
    let route_no_store = JmapRoute(Arc::new(JmapCommands {
        services: Some(Arc::new(services_no_store)),
        exec: exec.clone(),
        worker: Some(worker.clone()),
        denylist: None,
        keys: jwks.clone(),
        issuer: "mailserver".into(),
    }));
    let unused_upstream_1 = common::fake_upstream(|_| async {
        hyper::Response::builder()
            .status(299)
            .body(full("unused"))
            .unwrap()
    })
    .await;
    let gw_no_store = common::gateway(
        unused_upstream_1,
        "",
        RouteTable::proxy_all().with(route_no_store),
    )
    .await;

    // 1. Fail-closed signSMIME: missing S3Store rejects creation into notCreated (never unsigned).
    let token_a = e.token(e.a.user);
    let token_b = e.token(e.b.user);
    let post_gw = |addr: std::net::SocketAddr, tok: String, body: String| async move {
        let req = Request::post("/jmap")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("content-type", "application/json")
            .header("x-requested-with", "XMLHttpRequest")
            .header("authorization", format!("Bearer {tok}"))
            .body(full(body))
            .unwrap();
        let resp = common::send(addr, req).await;
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    };

    let sign_req = json!({
        "using": ["urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
        "methodCalls": [[
            "EmailSubmission/set",
            {
                "accountId": e.a.mailbox.to_string(),
                "create": {"s1": {"emailId": e.a.inbox_only.to_string(), "signSMIME": true}}
            },
            "c0"
        ]]
    })
    .to_string();
    let (st, raw) = post_gw(gw_no_store, token_a.clone(), sign_req.clone()).await;
    assert_eq!(st, 200);
    let doc: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        doc["methodResponses"][0][1]["notCreated"]["s1"]["type"],
        "smime_sign_failed"
    );
    assert!(doc["methodResponses"][0][1]["created"]["s1"].is_null());

    // 2. Wire full S3 + tight decrypt limiter (limit = 2) gateway.
    let mut services = JmapServices::new(worker.clone(), "mail.test".into(), 52_428_800);
    services.store = Some(store);
    services.decrypt_limiter = Some(Arc::new(Limiter::new(2, 60)));
    let route = JmapRoute(Arc::new(JmapCommands {
        services: Some(Arc::new(services)),
        exec,
        worker: Some(worker),
        denylist: None,
        keys: jwks,
        issuer: "mailserver".into(),
    }));
    let unused_upstream_2 = common::fake_upstream(|_| async {
        hyper::Response::builder()
            .status(299)
            .body(full("unused"))
            .unwrap()
    })
    .await;
    let gw = common::gateway(unused_upstream_2, "", RouteTable::proxy_all().with(route)).await;

    // Resolve emails of fixture users a and b.
    let email_a: String = e
        .owner
        .query_one("SELECT email FROM users WHERE id = $1", &[&e.a.user])
        .await
        .unwrap()
        .get(0);
    let email_b: String = e
        .owner
        .query_one("SELECT email FROM users WHERE id = $1", &[&e.b.user])
        .await
        .unwrap()
        .get(0);

    let (cert_a_pem, key_a_pem) =
        setjoin_smtp::smime::generate_rsa_smime_identity(&email_a, Some(true));
    let (cert_b_pem, key_b_pem) =
        setjoin_smtp::smime::generate_rsa_smime_identity(&email_b, Some(true));

    // Seed cert+key for a and b encrypted under ENC_KEY.
    for (uid, cpem, kpem) in [
        (e.a.user, &cert_a_pem, &key_a_pem),
        (e.b.user, &cert_b_pem, &key_b_pem),
    ] {
        e.owner
            .query_typed(
                "INSERT INTO user_smime_certs (user_id, label, cert_pem, private_key_enc, issued_at, expires_at, is_default) \
                 VALUES ($1, 'w2b', $2, pgp_sym_encrypt($3, $4), now() - interval '1 hour', now() + interval '24 hours', TRUE)",
                &[(&uid, Type::INT8), (cpem, Type::TEXT), (kpem, Type::TEXT), (&ENC_KEY, Type::TEXT)],
            )
            .await
            .unwrap();
    }

    // Grant delegate b full access on a's mailbox.
    e.owner
        .execute(
            "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
             VALUES ($1, $2, 'full_access', $3) ON CONFLICT (mailbox_id, user_id, permission) DO NOTHING",
            &[&e.a.mailbox, &e.b.user, &e.a.user],
        )
        .await
        .unwrap();

    // Seed attachment + inline draft body for a's inbox_only message.
    let att_bytes = b"WAVE2B-ATTACHMENT-PAYLOAD";
    let att_sha = format!("{:x}", Sha256::digest(att_bytes));
    objects
        .lock()
        .unwrap()
        .insert(att_sha.clone(), att_bytes.to_vec());
    let inline_draft = format!(
        "From: {email_a}\r\nTo: {email_b}\r\nSubject: Wave2b S/MIME Attach\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nConfidential attachment body\r\n"
    );
    let to_addrs_json = json!([{"email": email_b}]).to_string();
    let msg_recv: std::time::SystemTime = e
        .owner
        .query_one(
            "UPDATE messages SET from_addr = $1, to_addrs = $2::text::jsonb, raw_ref = $3, has_attachments = TRUE, is_read = FALSE \
             WHERE id = $4 AND mailbox_id = $5 RETURNING received_at",
            &[&email_a, &to_addrs_json, &inline_draft, &e.a.inbox_only, &e.a.mailbox],
        )
        .await
        .unwrap()
        .get(0);
    e.owner
        .execute(
            "INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type) VALUES ($1, $1, $2, 'application/pdf') ON CONFLICT DO NOTHING",
            &[&att_sha, &(att_bytes.len() as i64)],
        )
        .await
        .unwrap();
    e.owner
        .execute(
            "INSERT INTO message_attachments (message_id, received_at, blob_sha256, filename, content_type, disposition, size_bytes) \
             VALUES ($1, $2, $3, 'secret.pdf', 'application/pdf', 'attachment', $4)",
            &[&e.a.inbox_only, &msg_recv, &att_sha, &(att_bytes.len() as i64)],
        )
        .await
        .unwrap();

    // 3. Attachment-bearing EmailSubmission/set with signSMIME + encryptSMIME.
    let sign_enc_req = json!({
        "using": ["urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
        "methodCalls": [[
            "EmailSubmission/set",
            {
                "accountId": e.a.mailbox.to_string(),
                "create": {"s1": {"emailId": e.a.inbox_only.to_string(), "signSMIME": true, "encryptSMIME": true}}
            },
            "c0"
        ]]
    })
    .to_string();
    let (st, raw) = post_gw(gw, token_a.clone(), sign_enc_req).await;
    assert_eq!(st, 200);
    let doc: Value = serde_json::from_str(&raw).unwrap();
    assert!(
        doc["methodResponses"][0][1]["created"]["s1"].is_object(),
        "expected sign+encrypt attachment submission created: {doc}"
    );

    let sent_id: i64 = doc["methodResponses"][0][1]["created"]["s1"]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    // Fetch Sent copy raw_ref + verify size_bytes updated & independently decrypt + verify CMS signature.
    let sent_row = e
        .owner
        .query_one(
            "SELECT raw_ref, size_bytes FROM messages WHERE id = $1 AND mailbox_id = $2",
            &[&sent_id, &e.a.mailbox],
        )
        .await
        .unwrap();
    let q_raw_ref: String = sent_row.get(0);
    let updated_size: i64 = sent_row.get(1);
    let uploaded_wire = objects
        .lock()
        .unwrap()
        .get(&q_raw_ref)
        .expect("encrypted S3 blob uploaded")
        .clone();
    assert_eq!(updated_size, uploaded_wire.len() as i64);

    let dk_a = setjoin_smtp::smime::parse_decrypt_candidate(&cert_a_pem, &key_a_pem).unwrap();
    let dk_b = setjoin_smtp::smime::parse_decrypt_candidate(&cert_b_pem, &key_b_pem).unwrap();
    let der = setjoin_smtp::smime::decode_enveloped_der(&uploaded_wire).unwrap();
    let inner_signed_a = setjoin_smtp::smime::decrypt_multi(&der, &[dk_a]).unwrap();
    let inner_signed = setjoin_smtp::smime::decrypt_multi(&der, &[dk_b]).unwrap();
    assert_eq!(inner_signed_a, inner_signed);
    let verified_entity =
        setjoin_smtp::smime::verify_multipart_signed_with_cert(&inner_signed, &cert_a_pem)
            .expect("detached CMS signature must verify with sender cert");
    let verified_str = String::from_utf8_lossy(&verified_entity);
    assert!(verified_str.contains("multipart/mixed"), "{verified_str}");
    assert!(verified_str.contains("Confidential attachment body"));
    assert!(verified_str.contains("secret.pdf"), "{verified_str}");
    let att_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, att_bytes);
    assert!(verified_str.contains(&att_b64), "{verified_str}");

    // 3b. Fail-closed numeric emailId + soft notCreated lease rejection restores draft size_bytes.
    let bad_email_id_req = json!({
        "using": ["urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
        "methodCalls": [[
            "EmailSubmission/set",
            {
                "accountId": e.a.mailbox.to_string(),
                "create": {"s1": {"emailId": 123, "signSMIME": true}}
            },
            "c_num"
        ]]
    })
    .to_string();
    let (st, raw_num) = post_gw(gw, token_a.clone(), bad_email_id_req).await;
    assert_eq!(st, 200);
    let doc_num: Value = serde_json::from_str(&raw_num).unwrap();
    assert!(doc_num["methodResponses"][0][1]["notCreated"]["s1"].is_object());
    assert!(doc_num["methodResponses"][0][1]["created"]["s1"].is_null());

    e.owner
        .execute(
            "UPDATE messages SET from_addr = $1, to_addrs = $2::text::jsonb, raw_ref = $3, size_bytes = 42 WHERE id = $4 AND mailbox_id = $5",
            &[&email_a, &to_addrs_json, &inline_draft, &e.a.two_labels, &e.a.mailbox],
        )
        .await
        .unwrap();
    let lease_fail_req = json!({
        "using": ["urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
        "methodCalls": [[
            "EmailSubmission/set",
            {
                "accountId": e.a.mailbox.to_string(),
                "create": {
                    "s1": {
                        "emailId": e.a.two_labels.to_string(),
                        "signSMIME": true,
                        "draftSessionId": "00000000-0000-0000-0000-000000000001",
                        "draftLeaseEpoch": 1,
                        "draftRevision": 1
                    }
                }
            },
            "c_lease"
        ]]
    })
    .to_string();
    let (st, raw_lease) = post_gw(gw, token_a.clone(), lease_fail_req).await;
    assert_eq!(st, 200);
    let doc_lease: Value = serde_json::from_str(&raw_lease).unwrap();
    assert!(doc_lease["methodResponses"][0][1]["notCreated"]["s1"].is_object());
    assert!(doc_lease["methodResponses"][0][1]["created"]["s1"].is_null());
    let preserved_size: i64 = e
        .owner
        .query_one(
            "SELECT size_bytes FROM messages WHERE id = $1 AND mailbox_id = $2",
            &[&e.a.two_labels, &e.a.mailbox],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(preserved_size, 42);

    // 4. Email/get decrypt-on-read: encrypt multi-byte payload straddling 256-byte boundary ONLY for owner `a`.
    let mut pt_256 = vec![b'x'; 255];
    pt_256.extend_from_slice("😀after-boundary".as_bytes());
    let cert_a = setjoin_smtp::smime::parse_cert_pem(&cert_a_pem).unwrap();
    let enc_for_a = setjoin_smtp::smime::encrypt_message(
        &pt_256,
        &[cert_a],
        setjoin_smtp::smime::EncryptAlgorithm::Aes256Gcm,
    )
    .unwrap();
    let enc_key = format!("{:x}", Sha256::digest(&enc_for_a));
    objects.lock().unwrap().insert(enc_key.clone(), enc_for_a);
    e.owner
        .execute(
            "UPDATE messages SET crypto_type = 'smime-encrypted', raw_ref = $1, body_text = NULL, body_html = '<p>keep</p>' WHERE id = $2 AND mailbox_id = $3",
            &[&enc_key, &e.a.two_labels, &e.a.mailbox],
        )
        .await
        .unwrap();

    // 4a. Delegate `b` (holding `b`'s own cert/key + write grant on `a`'s mailbox) calls Email/get ->
    //     MUST use $actor (b)'s key (yielding wrong_key) and NEVER borrow owner a's key!
    let get_enc_req = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/get", {"accountId": e.a.mailbox.to_string(), "ids": [e.a.two_labels.to_string()]}, "g0"]]
    })
    .to_string();
    let (st, raw_del) = post_gw(gw, token_b, get_enc_req.clone()).await;
    assert_eq!(st, 200);
    let doc_del: Value = serde_json::from_str(&raw_del).unwrap();
    let del_item = &doc_del["methodResponses"][0][1]["list"][0];
    assert_eq!(del_item["decryptState"], "wrong_key");
    assert!(del_item["bodyText"].is_null());

    // 4b. Owner `a` calls Email/get on the reused size-1 worker connection (charges 1 of 2 budget):
    //     decryptState=decrypted, 256-byte preview sliced pre-lossy, bodyHTML preserved,
    //     email_decrypt_read audit row recorded with real mailbox_id + actor_user_id + message_id.
    let (st, raw_a1) = post_gw(gw, token_a.clone(), get_enc_req.clone()).await;
    assert_eq!(st, 200);
    let doc_a1: Value = serde_json::from_str(&raw_a1).unwrap();
    let a1_item = &doc_a1["methodResponses"][0][1]["list"][0];
    assert_eq!(a1_item["decryptState"], "decrypted");
    assert_eq!(a1_item["bodyHTML"], "<p>keep</p>");
    assert_eq!(a1_item["preview"], format!("{}\u{FFFD}", "x".repeat(255)));
    assert!(a1_item["bodyText"]
        .as_str()
        .unwrap()
        .ends_with("😀after-boundary"));
    let dec_audits: i64 = e
        .owner
        .query_one(
            "SELECT count(*) FROM mailbox_audit_log WHERE mailbox_id = $1 AND actor_user_id = $2 AND action = 'email_decrypt_read' AND message_id = $3",
            &[&e.a.mailbox, &e.a.user, &e.a.two_labels],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(dec_audits, 1);

    // 4c. 2nd decrypt for `a` succeeds, 3rd hits per-user decrypt budget -> decryptState=error without S3 read.
    let (st, raw_a2) = post_gw(gw, token_a.clone(), get_enc_req.clone()).await;
    assert_eq!(st, 200);
    let doc_a2: Value = serde_json::from_str(&raw_a2).unwrap();
    assert_eq!(
        doc_a2["methodResponses"][0][1]["list"][0]["decryptState"],
        "decrypted"
    );

    let (st, raw_a3) = post_gw(gw, token_a, get_enc_req).await;
    assert_eq!(st, 200);
    let doc_a3: Value = serde_json::from_str(&raw_a3).unwrap();
    assert_eq!(
        doc_a3["methodResponses"][0][1]["list"][0]["decryptState"],
        "error"
    );
    assert!(doc_a3["methodResponses"][0][1]["list"][0]["bodyText"].is_null());

    // Cleanup extra seeded rows so fixture::remove tears down cleanly.
    let _ = e
        .owner
        .execute(
            "DELETE FROM mailbox_delegates WHERE mailbox_id = $1",
            &[&e.a.mailbox],
        )
        .await;
    let _ = e
        .owner
        .execute(
            "DELETE FROM message_attachments WHERE blob_sha256 = $1",
            &[&att_sha],
        )
        .await;
    let _ = e
        .owner
        .execute("DELETE FROM blobs WHERE sha256 = $1", &[&att_sha])
        .await;
    let _ = e
        .owner
        .execute(
            "DELETE FROM outbound_queue WHERE mailbox_id = $1",
            &[&e.a.mailbox],
        )
        .await;
    let _ = e
        .owner
        .execute(
            "DELETE FROM user_smime_certs WHERE user_id IN ($1, $2)",
            &[&e.a.user, &e.b.user],
        )
        .await;
});
