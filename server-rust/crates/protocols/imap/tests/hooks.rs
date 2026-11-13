//! The explicit #420 (threat) and #302 (webhook) seams. Frozen Go's threat
//! interceptor needs feeds, lockout state and policy rows, so these cases are
//! authored from `handleLogin` rather than recorded; the policy goldens that
//! replay through the listener belong to #420. They pin the ORDER of calls and
//! the wire/audit outcome for each decision.
mod common;
use common::*;
use futures_util::future::BoxFuture;
use setjoin_imap::{
    AuthWebhooks, ConnectionMeta, Server, ThreatAction, ThreatGate, ThreatPolicy, WebhookPolicy,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

#[derive(Default)]
struct Gate {
    pre: Mutex<Option<(ThreatAction, Duration)>>,
    post: Mutex<Option<(ThreatAction, String)>>,
    calls: Mutex<Vec<String>>,
}
impl ThreatGate for Gate {
    fn intercept<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
    ) -> BoxFuture<'a, (ThreatAction, Duration)> {
        self.calls.lock().unwrap().push(format!(
            "intercept ip={} user={} app={}",
            meta.source_ip, meta.username, meta.app_password
        ));
        let decision = self
            .pre
            .lock()
            .unwrap()
            .unwrap_or((ThreatAction::Allow, Duration::ZERO));
        Box::pin(async move { decision })
    }
    fn record_result<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
        ok: bool,
        user: i64,
    ) -> BoxFuture<'a, ()> {
        self.calls.lock().unwrap().push(format!(
            "record ok={ok} user={user} app={}",
            meta.app_password
        ));
        Box::pin(async {})
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        meta: &'a mut ConnectionMeta,
    ) -> BoxFuture<'a, (ThreatAction, String)> {
        self.calls.lock().unwrap().push(format!(
            "post user={} device_bound={}",
            meta.user_id, meta.device_bound
        ));
        let decision = self
            .post
            .lock()
            .unwrap()
            .clone()
            .unwrap_or((ThreatAction::Allow, String::new()));
        Box::pin(async move { decision })
    }
}

#[derive(Default)]
struct Hooks(Mutex<Vec<String>>);
impl AuthWebhooks for Hooks {
    fn login<'a>(&'a self, email: &'a str, provider: &'a str, ip: &'a str) -> BoxFuture<'a, ()> {
        self.0
            .lock()
            .unwrap()
            .push(format!("login {email} {provider} {ip}"));
        Box::pin(async {})
    }
    fn login_failed<'a>(
        &'a self,
        email: &'a str,
        provider: &'a str,
        ip: &'a str,
    ) -> BoxFuture<'a, ()> {
        self.0
            .lock()
            .unwrap()
            .push(format!("failed {email} {provider} {ip}"));
        Box::pin(async {})
    }
}

async fn exchange(socket: &mut TcpStream, request: &str, tag: &str) -> String {
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    let marker = format!("\r\n{tag} ");
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut chunk))
            .await
            .expect("reply")
            .unwrap();
        assert!(n > 0, "closed early: {}", String::from_utf8_lossy(&out));
        out.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&out);
        if (text.contains(&marker) || text.starts_with(&format!("{tag} ")))
            && text.ends_with("\r\n")
        {
            return text.into_owned();
        }
    }
}

struct Rig {
    gate: Arc<Gate>,
    hooks: Arc<Hooks>,
    socket: TcpStream,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn rig(db: &setjoin_conformance::harness::Db) -> Rig {
    let gate = Arc::new(Gate::default());
    let hooks = Arc::new(Hooks::default());
    let server = Server::new(
        executor(db),
        ThreatPolicy::Enforced(gate.clone()),
        WebhookPolicy::Wired(hooks.clone()),
    );
    assert!(server.threat_enforced());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(server).serve(listener, rx));
    let mut socket = TcpStream::connect(addr).await.unwrap();
    exchange(&mut socket, "", "*").await;
    Rig {
        gate,
        hooks,
        socket,
        stop,
        task,
    }
}

impl Rig {
    async fn finish(self) {
        drop(self.socket);
        self.stop.send(true).unwrap();
        self.task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn threat_decisions_gate_login_in_gos_order() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("imap-threat-hook") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    seed(&owner).await;
    let hashes: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/password-hashes.json")).unwrap();
    reset_fixture(&owner, &hashes).await;
    let login = "a1 LOGIN \"alice@imap1.test\" \"IMAP1-correct-password!\"\r\n";

    // Reject: no credential check at all, so no app-password audit row either.
    let mut r = rig(&db).await;
    *r.gate.pre.lock().unwrap() = Some((ThreatAction::Reject, Duration::ZERO));
    let reply = exchange(&mut r.socket, login, "a1").await;
    assert_eq!(reply, "a1 NO Authentication temporarily unavailable\r\n");
    assert_eq!(
        *r.gate.calls.lock().unwrap(),
        vec!["intercept ip=127.0.0.1 user=alice@imap1.test app=false"]
    );
    assert!(events(&owner).await.is_empty());
    assert!(r.hooks.0.lock().unwrap().is_empty());
    r.finish().await;

    // Tarpit: the delay is served before the same refusal.
    let mut r = rig(&db).await;
    *r.gate.pre.lock().unwrap() = Some((ThreatAction::Tarpitted, Duration::from_millis(400)));
    let started = Instant::now();
    let reply = exchange(&mut r.socket, login, "a1").await;
    assert!(started.elapsed() >= Duration::from_millis(400));
    assert_eq!(reply, "a1 NO Authentication temporarily unavailable\r\n");
    r.finish().await;

    // Rate limit: its own text (with an em dash).
    let mut r = rig(&db).await;
    *r.gate.pre.lock().unwrap() = Some((ThreatAction::RateLimited, Duration::ZERO));
    let reply = exchange(&mut r.socket, login, "a1").await;
    assert_eq!(
        reply,
        "a1 NO Too many authentication attempts \u{2014} try again later\r\n"
    );
    r.finish().await;

    // Failed credentials record a failure with user 0 and dispatch the failure webhook.
    let mut r = rig(&db).await;
    let reply = exchange(
        &mut r.socket,
        "a1 LOGIN \"alice@imap1.test\" \"wrong\"\r\n",
        "a1",
    )
    .await;
    assert_eq!(reply, "a1 NO Authentication failed\r\n");
    assert_eq!(
        *r.gate.calls.lock().unwrap(),
        vec![
            "intercept ip=127.0.0.1 user=alice@imap1.test app=false",
            "record ok=false user=0 app=false"
        ]
    );
    assert_eq!(
        *r.hooks.0.lock().unwrap(),
        vec!["failed alice@imap1.test bcrypt 127.0.0.1"]
    );
    r.finish().await;

    // Success then a post-auth policy denial: identity is dropped again.
    let mut r = rig(&db).await;
    *r.gate.post.lock().unwrap() = Some((ThreatAction::Reject, "GEO_BLOCKED".into()));
    let reply = exchange(&mut r.socket, login, "a1").await;
    assert_eq!(reply, "a1 NO [GEO_BLOCKED] Access blocked by policy\r\n");
    assert_eq!(
        *r.gate.calls.lock().unwrap(),
        vec![
            "intercept ip=127.0.0.1 user=alice@imap1.test app=false",
            "record ok=true user=9343011 app=false",
            "post user=9343011 device_bound=false"
        ]
    );
    assert_eq!(
        exchange(&mut r.socket, "a2 SELECT Inbox\r\n", "a2").await,
        "a2 NO Authentication required\r\n"
    );
    r.finish().await;

    // App password: flagged for the policy, webhook names the provider.
    let mut r = rig(&db).await;
    let reply = exchange(
        &mut r.socket,
        "a1 LOGIN \"alice@imap1.test\" \"imap1-app-token-valid\"\r\n",
        "a1",
    )
    .await;
    assert!(reply.starts_with("a1 OK [CAPABILITY"), "{reply}");
    assert_eq!(
        *r.gate.calls.lock().unwrap(),
        vec![
            "intercept ip=127.0.0.1 user=alice@imap1.test app=false",
            "record ok=true user=9343011 app=true",
            "post user=9343011 device_bound=false"
        ]
    );
    assert_eq!(
        *r.hooks.0.lock().unwrap(),
        vec!["login alice@imap1.test app_password 127.0.0.1"]
    );
    r.finish().await;
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
}
