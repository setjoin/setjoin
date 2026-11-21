//! Wave 1 (#356) integration tests:
//! 1. HTTP transport errors (`400` `notJSON`/`notRequest`/`requestTooLarge`/`unknownCapability`),
//!    10 MB `JMAP_BODY_CAP`, and auth-first untouched forwarding (`299`).
//! 2. Multi-call HTTP batches, `#resultReference`, `createdIds`, 0-call envelope parity,
//!    and distinct per-call `OperationId`s.
//! 3. Ordered preflight before Call 0 (zero partial writes / zero Rust audits).
//! 4. Non-Family delegated accounts permission matrix under V090 FORCE-RLS (`setjoin_app`).
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
    let runtime =
        setjoin_gateway::runtime_access::RuntimeAccess::new(exec, jwks, "mailserver".into())
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
    // 1. Auth-first: unauthenticated or unsupported tokens forward malformed bodies to Go untouched.
    let vectors: Value =
        serde_json::from_str(include_str!("golden/go-unsupported-tokens.json")).unwrap();
    let hs256 = vectors["hs256"].as_str().unwrap();
    for (label, auth, body) in [
        ("missing auth + bad json", None, "{"),
        ("garbage token + bad json", Some("a.b.c"), "{"),
        ("hs256 token + null", Some(hs256), "null"),
    ] {
        let (status, _, text, hit) = e.post_raw(auth, body).await;
        assert_eq!(
            (status, text.as_str(), hit),
            (299, "from go", true),
            "{label}"
        );
    }

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
            .as_object()
            .is_some_and(|m| m.contains_key(&e.a.two_labels.to_string())),
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

        // Case A: Email/set (seen) followed by Email/set with create -> defers before Call 0.
        let before = fixture::snapshot(&e.owner, e.a.mailbox).await.unwrap();
        let audit = e.audit_rows(e.a.mailbox).await;
        let req_create = json!({
        "using": ["urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Email/set", {"accountId": mb, "update": {e.a.inbox_only.to_string(): {"keywords": {"$seen": true}}}}, "c0"],
            ["Email/set", {"accountId": mb, "create": {"draft": {"subject": "hi"}}}, "c1"]
        ]
    })
    .to_string();
        let (status, _, hit) = e.post(&token, &req_create).await;
        assert_eq!((status, hit), (299, true));
        assert!(!e.is_read(e.a.inbox_only).await);
        assert_eq!(
            fixture::snapshot(&e.owner, e.a.mailbox).await.unwrap(),
            before
        );
        assert_eq!(e.audit_rows(e.a.mailbox).await, audit);

        // Case B: Email/set followed by EmailSubmission/set targeting message with attachments.
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
        assert_eq!((status, hit), (299, true));
        assert!(!e.is_read(e.a.inbox_only).await);
        assert_eq!(e.audit_rows(e.a.mailbox).await, audit);

        // Case C: Email/set followed by Email/get (#ids) in mailbox with smime-encrypted message.
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
        let (status, _, hit) = e.post(&token, &req_enc_ref).await;
        assert_eq!((status, hit), (299, true));
        assert!(!e.is_read(e.a.inbox_only).await);
        assert_eq!(e.audit_rows(e.a.mailbox).await, audit);
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

    // 6. Delegated Email/get on smime-encrypted message uses target_auth & defers before Call 0.
    e.owner
        .execute(
            "UPDATE messages SET crypto_type = 'smime-encrypted' WHERE id = $1 AND mailbox_id = $2",
            &[&e.b.two_labels, &e.b.mailbox],
        )
        .await
        .unwrap();
    let (status, _, hit) = e
        .post(
            &delegate_token,
            &call(
                &["urn:ietf:params:jmap:mail"],
                "Email/get",
                json!({"accountId": target_mb, "ids": [e.b.two_labels.to_string()]}),
            ),
        )
        .await;
    assert_eq!((status, hit), (299, true));

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
