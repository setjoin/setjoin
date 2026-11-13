//! Owned process-local HA deployment, mirroring frozen Go's SSH state machine.
mod commands;
mod ssh;
use serde::Serialize;
use setjoin_authz::AuthContext;
use setjoin_pg::{ScopedExecutor, Type};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{watch, Mutex};
use tokio_util::sync::CancellationToken;
const WITHHELD:&str="[withheld: persisted step detail removed at restore — pre-redaction rows cannot be verified secret-free; reconcile on the target host]";
#[derive(Clone, Default)]
pub struct Node {
    pub host: String,
    pub role: String,
    pub ssh_user: String,
    pub ssh_key: String,
    pub password: String,
}
#[derive(Clone)]
pub struct Config {
    pub host_key: String,
    pub checksum: String,
    pub credentials: Arc<dyn Fn() -> (String, String) + Send + Sync>,
}
impl Config {
    pub fn fixed(host_key: String, checksum: String, pair: (String, String)) -> Self {
        Self {
            host_key,
            checksum,
            credentials: Arc::new(move || pair.clone()),
        }
    }
    pub fn environment() -> Self {
        Self {
            host_key: std::env::var("DEPLOY_HOST_KEY").unwrap_or_default(),
            checksum: std::env::var("DEPLOY_SEAWEEDFS_SHA256").unwrap_or_default(),
            credentials: Arc::new(|| {
                (
                    std::env::var("S3_ACCESS_KEY")
                        .ok()
                        .filter(|v| !v.is_empty())
                        .or_else(|| std::env::var("MINIO_ACCESS_KEY").ok())
                        .unwrap_or_default(),
                    std::env::var("S3_SECRET_KEY")
                        .ok()
                        .filter(|v| !v.is_empty())
                        .or_else(|| std::env::var("MINIO_SECRET_KEY").ok())
                        .unwrap_or_default(),
                )
            }),
        }
    }
}
// Go strings can retain arbitrary SSH bytes; encoding/json replaces each invalid
// byte with the literal escape \ufffd while PostgreSQL rejects the same text.
#[derive(Clone, Default)]
struct GoText(Vec<u8>);
impl GoText {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl From<String> for GoText {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}
impl From<&str> for GoText {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}
impl Serialize for GoText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let mut remaining = self.0.as_slice();
        let mut json = String::from("\"");
        loop {
            let (valid, invalid) = match std::str::from_utf8(remaining) {
                Ok(valid) => (valid, false),
                Err(error) => (
                    std::str::from_utf8(&remaining[..error.valid_up_to()])
                        .expect("validated prefix"),
                    true,
                ),
            };
            let encoded = serde_json::to_string(valid).map_err(S::Error::custom)?;
            json.push_str(&encoded[1..encoded.len() - 1]);
            if !invalid {
                break;
            }
            json.push_str("\\ufffd");
            remaining = &remaining[valid.len() + 1..];
        }
        json.push('"');
        serde_json::value::RawValue::from_string(json)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}
#[derive(Clone, Serialize)]
struct Step {
    name: String,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    output: String,
    #[serde(skip_serializing_if = "GoText::is_empty")]
    error: GoText,
}
#[derive(Clone)]
struct Run {
    cancel: CancellationToken,
    done: watch::Receiver<bool>,
    unknown: Arc<AtomicBool>,
}
struct State {
    nodes: Vec<Node>,
    steps: Vec<Step>,
    status: String,
    log: Vec<GoText>,
    started_at: String,
    run: Option<Run>,
    fenced: bool,
    /// The fence is also a `deploy_remote_fence` row (so an operator can clear it with SQL).
    fence_persisted: bool,
}
impl Default for State {
    fn default() -> Self {
        Self {
            nodes: vec![],
            steps: vec![],
            status: String::new(),
            log: vec![],
            started_at: "0001-01-01T00:00:00Z".into(),
            run: None,
            fenced: false,
            fence_persisted: false,
        }
    }
}
struct Inner {
    state: Mutex<State>,
    worker: ScopedExecutor,
    config: Config,
}
pub struct Wizard {
    inner: Arc<Inner>,
    stop: CancellationToken,
}
/// Strict node host (#542, owner-approved security fix 2026-11-05): a DNS hostname, an IPv4
/// literal or a bracketed IPv6 literal, with an optional `:port`. Frozen Go interpolated the
/// raw field into remote shell commands. Everything else (quotes, `;`, whitespace, newlines,
/// `$`, backticks) is refused before any command is built.
pub fn valid_host(host: &str) -> bool {
    // Test-only bug restoration (deploy-node-unvalidated).
    if setjoin_contracts::mutants::on("deploy-node-unvalidated") {
        return true;
    }
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) if !name.ends_with(']') && !name.contains(':') => (name, Some(port)),
        Some((name, port)) if name.ends_with(']') => (name, Some(port)),
        _ => (host, None),
    };
    if port.is_some_and(|p| p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u32>().map_or(true, |n| n == 0 || n > 65535)) {
        return false;
    }
    if let Some(inner) = name.strip_prefix('[').and_then(|n| n.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if name.is_empty() || name.len() > 253 || name.contains(':') {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
/// Strict POSIX-style SSH user name.
pub fn valid_user(user: &str) -> bool {
    if setjoin_contracts::mutants::on("deploy-node-unvalidated") {
        return true;
    }
    let mut chars = user.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && user.len() <= 32
        && user.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
/// The request-time check of every node field that reaches a command or a connection.
pub fn validate(nodes: &[Node]) -> Result<(), &'static str> {
    for node in nodes {
        if !valid_host(&node.host) {
            return Err("invalid node host");
        }
        if !valid_user(&node.ssh_user) {
            return Err("invalid ssh_user");
        }
    }
    Ok(())
}
/// POSIX shell single-quoting. Strings made only of shell-safe characters stay as they are, so
/// every ordinary command keeps its reviewed bytes.
pub(crate) fn sh_quote(text: &str) -> String {
    if setjoin_contracts::mutants::on("deploy-host-unquoted") {
        return text.to_owned();
    }
    if !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'))
    {
        return text.to_owned();
    }
    format!("'{}'", text.replace('\'', "'\\''"))
}
fn inline(key: &str) -> bool {
    key.trim().starts_with("-----")
}
fn secrets(nodes: &[Node]) -> Vec<String> {
    nodes
        .iter()
        .flat_map(|n| {
            [
                if inline(&n.ssh_key) {
                    n.ssh_key.trim().into()
                } else {
                    String::new()
                },
                n.password.clone(),
            ]
        })
        .filter(|v| !v.is_empty())
        .collect()
}
fn redact(text: &[u8], secrets: &[String]) -> Vec<u8> {
    let key = regex::bytes::RegexBuilder::new(
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
    )
    .unicode(false)
    .build()
    .unwrap();
    let pass = regex::bytes::RegexBuilder::new(r"(?i)(health_check_password\s*=\s*')[^']*(')")
        .unicode(false)
        .build()
        .unwrap();
    let text = key.replace_all(text, &b"[REDACTED]"[..]);
    let text = pass
        .replace_all(&text, &b"${1}[REDACTED]${2}"[..])
        .into_owned();
    let mut spans = vec![];
    for secret in secrets.iter().filter(|v| !v.is_empty()) {
        let mut from = 0;
        while let Some(i) = text[from..]
            .windows(secret.len())
            .position(|v| v == secret.as_bytes())
        {
            let start = from + i;
            spans.push((start, start + secret.len()));
            from = start + 1;
        }
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = vec![];
    for (a, b) in spans {
        if let Some(last) = merged.last_mut().filter(|last| a <= last.1) {
            last.1 = last.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    let mut out = Vec::new();
    let mut from = 0;
    for (a, b) in merged {
        out.extend_from_slice(&text[from..a]);
        out.extend_from_slice(b"[REDACTED]");
        from = b;
    }
    out.extend_from_slice(&text[from..]);
    if out.len() > 4096 {
        out.truncate(4096);
        out.extend_from_slice(b"\n...[truncated]");
    }
    out
}
impl Wizard {
    pub async fn load(worker: ScopedExecutor, config: Config) -> Self {
        let mut state = State::default();
        if let Ok(rows)=worker.read("SELECT step_name,status,COALESCE(output,''),COALESCE(error,'') FROM deployment_steps ORDER BY step_name",&[]).await{for row in rows{let(Ok(name),Ok(mut status),Ok(output),Ok(error))=(row.try_get::<_,String>(0),row.try_get::<_,String>(1),row.try_get::<_,String>(2),row.try_get::<_,String>(3))else{continue;};if status=="running"{status="failed".into();}state.steps.push(Step{name,status,output:if output.is_empty(){String::new()}else{WITHHELD.into()},error:if error.is_empty(){GoText::default()}else{WITHHELD.into()}});}if !state.steps.is_empty(){state.status="resumed".into();}}
        // #542 (owner-approved security fix 2026-11-05): the unresolved remote-command fence is
        // durable. Test-only bug restoration (deploy-fence-memory-only): ignore the row.
        if !setjoin_contracts::mutants::on("deploy-fence-memory-only") {
            match worker.read("SELECT count(*)::bigint FROM deploy_remote_fence",&[]).await.ok().and_then(|r|r.first().and_then(|r|r.try_get::<_,i64>(0).ok())){
                Some(0)=>{}
                Some(_)=>{state.fenced=true;state.fence_persisted=true;}
                // Unreadable: refuse new runs rather than run past a fence that may exist (re-checked at begin).
                None=>{state.fenced=true;state.fence_persisted=true;}
            }
        }
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(state),
                worker,
                config,
            }),
            stop: CancellationToken::new(),
        }
    }
    pub fn shutdown(&self) {
        self.stop.cancel();
    }
    pub async fn reset(&self) {
        let run = {
            let mut state = self.inner.state.lock().await;
            if let Some(run) = &state.run {
                run.cancel.cancel();
                Some(run.clone())
            } else {
                let (fenced, persisted) = (state.fenced, state.fence_persisted);
                *state = State::default();
                state.fenced = fenced;
                state.fence_persisted = persisted;
                None
            }
        };
        if let Some(mut run) = run {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !*run.done.borrow() {
                    if run.done.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
        }
    }
    pub async fn begin(&self, nodes: Vec<Node>, actor: AuthContext) -> Result<(), String> {
        let mut state = self.inner.state.lock().await;
        if state.fenced && state.fence_persisted && self.inner.fence_row_absent().await {
            // The operator resolved the fence (DELETE FROM deploy_remote_fence).
            state.fenced = false;
            state.fence_persisted = false;
        }
        if state.fenced && !state.fence_persisted && self.inner.persist_fence(&actor).await {
            // A fence that could not be written earlier is retried before any run is admitted.
            state.fence_persisted = true;
        }
        if state.fenced {
            return Err("previous deployment ended with unconfirmed remote termination".into());
        }
        if state.run.is_some() {
            return Err("deployment already in progress".into());
        }
        let (done_tx, done) = watch::channel(false);
        let run = Run {
            cancel: self.stop.child_token(),
            done,
            unknown: Arc::new(AtomicBool::new(false)),
        };
        *state = State {
            nodes: nodes.clone(),
            status: "deploying".into(),
            started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            run: Some(run.clone()),
            ..State::default()
        };
        let inner = self.inner.clone();
        tokio::spawn(async move {
            inner.execute(nodes, actor.clone(), run.clone()).await;
            let fence = run.cancel.is_cancelled() && run.unknown.load(Ordering::Acquire);
            // Durable before the run is reported finished.
            let persisted = fence && inner.persist_fence(&actor).await;
            if fence && !persisted {
                eprintln!("deploy: FAILED to persist the remote-command fence; refusing new runs in this process until it is written");
            }
            let mut state = inner.state.lock().await;
            if fence {
                state.fenced = true;
                state.fence_persisted = persisted;
            }
            state.run = None;
            drop(state);
            let _ = done_tx.send(true);
        });
        Ok(())
    }
    pub async fn status(&self) -> String {
        #[derive(Serialize)]
        struct NodeStatus<'a> {
            host: &'a str,
            role: &'a str,
            ssh_user: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            key_path: Option<&'a str>,
            #[serde(skip_serializing_if = "is_false")]
            has_inline_key: bool,
        }
        fn is_false(v: &bool) -> bool {
            !*v
        }
        #[derive(Serialize)]
        struct Projection<'a> {
            profile: i32,
            nodes: Vec<NodeStatus<'a>>,
            steps: Option<&'a Vec<Step>>,
            status: &'a str,
            log: Option<&'a Vec<GoText>>,
            started_at: &'a str,
        }
        let state = self.inner.state.lock().await;
        let nodes = state
            .nodes
            .iter()
            .map(|n| NodeStatus {
                host: &n.host,
                role: &n.role,
                ssh_user: &n.ssh_user,
                key_path: (!inline(&n.ssh_key) && !n.ssh_key.is_empty())
                    .then_some(n.ssh_key.as_str()),
                has_inline_key: inline(&n.ssh_key),
            })
            .collect();
        String::from_utf8(
            setjoin_release_format::marshal_go(&Projection {
                profile: 0,
                nodes,
                steps: (!state.steps.is_empty()).then_some(&state.steps),
                status: &state.status,
                log: (!state.log.is_empty()).then_some(&state.log),
                started_at: &state.started_at,
            })
            .unwrap(),
        )
        .unwrap()
            + "\n"
    }
}
impl Drop for Wizard {
    fn drop(&mut self) {
        self.shutdown();
    }
}
impl Inner {
    async fn fence_row_absent(&self) -> bool {
        self.worker
            .read("SELECT count(*)::bigint FROM deploy_remote_fence", &[])
            .await
            .ok()
            .and_then(|r| r.first().and_then(|r| r.try_get::<_, i64>(0).ok()))
            == Some(0)
    }
    async fn persist_fence(&self, actor: &AuthContext) -> bool {
        if setjoin_contracts::mutants::on("deploy-fence-memory-only") {
            return false;
        }
        let mut operation = [0; 16];
        if getrandom::getrandom(&mut operation).is_err() {
            return false;
        }
        let detail = "deployment cancelled with unconfirmed remote command termination";
        matches!(crate::upgrades::write(&self.worker,actor,"deploy_fence_set","INSERT INTO deploy_remote_fence(id,actor_user_id,detail) SELECT true,$1::bigint,$4::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' ON CONFLICT(id) DO UPDATE SET detail=EXCLUDED.detail RETURNING 'null'::text",&[(&detail,Type::TEXT)],operation).await,setjoin_pg::CommandOutcome::Committed(_))
    }
    async fn persist(&self, step: &Step, actor: &AuthContext, nodes: &[Node]) {
        let secret = secrets(nodes);
        let output = redact(step.output.as_bytes(), &secret);
        let error = redact(&step.error.0, &secret);
        let mut operation = [0; 16];
        if getrandom::getrandom(&mut operation).is_err() {
            return;
        }
        let _=crate::upgrades::write(&self.worker,actor,"deployment_step_upsert","INSERT INTO deployment_steps(step_name,status,output,error,started_at,completed_at) SELECT $4::text,$5::text,convert_from($6::bytea,'UTF8'),convert_from($7::bytea,'UTF8'),now(),CASE WHEN $5::text IN ('done','failed') THEN now() END WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' ON CONFLICT(step_name) DO UPDATE SET status=EXCLUDED.status,output=EXCLUDED.output,error=EXCLUDED.error,started_at=COALESCE(deployment_steps.started_at,EXCLUDED.started_at),completed_at=CASE WHEN EXCLUDED.status IN ('done','failed') THEN now() ELSE deployment_steps.completed_at END RETURNING 'null'::text",&[(&step.name,Type::TEXT),(&step.status,Type::TEXT),(&output,Type::BYTEA),(&error,Type::BYTEA)],operation).await;
    }
    async fn execute(self: &Arc<Self>, nodes: Vec<Node>, actor: AuthContext, run: Run) {
        for (index, (name, description)) in commands::STAGES.iter().enumerate() {
            {
                let mut state = self.state.lock().await;
                state.steps.push(Step {
                    name: (*name).into(),
                    status: "running".into(),
                    output: String::new(),
                    error: GoText::default(),
                });
                state.log.push(format!("[{name}] {description}").into());
            }
            let result = async {
                let jobs =
                    commands::build(index, &nodes, &self.config).map_err(String::into_bytes)?;
                for job in jobs {
                    let credentials = &nodes[job.credentials];
                    match ssh::call(
                        &nodes[job.node].host,
                        &credentials.ssh_user,
                        &credentials.ssh_key,
                        &job.command,
                        &self.config,
                        &run,
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err((error, output)) => {
                            let mut extra = secrets(&nodes);
                            extra.extend(job.secrets);
                            let error = redact(error.as_bytes(), &extra);
                            let output = redact(&output, &extra);
                            if job.nonfatal {
                                continue;
                            }
                            let mut detail = job.prefix.into_bytes();
                            detail.extend(error);
                            detail.extend_from_slice(job.divider.as_bytes());
                            detail.extend(output);
                            detail.extend_from_slice(job.suffix.as_bytes());
                            return Err(detail);
                        }
                    }
                }
                Ok::<_, Vec<u8>>(())
            }
            .await;
            let mut state = self.state.lock().await;
            let failed = result.err().map(|error| redact(&error, &secrets(&nodes)));
            let step = state.steps.last_mut().unwrap();
            step.status = if failed.is_some() { "failed" } else { "ok" }.into();
            if let Some(error) = &failed {
                step.error = GoText(error.clone());
            }
            self.persist(step, &actor, &nodes).await;
            state.log.push(if let Some(error) = &failed {
                let mut line = format!("[{name}] FAILED: ").into_bytes();
                line.extend(error);
                GoText(line)
            } else {
                format!("[{name}] OK").into()
            });
            if failed.is_some() {
                state.status = "failed".into();
                return;
            }
        }
        self.state.lock().await.status = "done".into();
    }
}

#[cfg(test)]
mod secfix11_tests {
    use super::*;
    fn node(host: &str, role: &str) -> Node {
        Node {
            host: host.into(),
            role: role.into(),
            ssh_user: "root".into(),
            ssh_key: String::new(),
            password: String::new(),
        }
    }
    /// #542: only hostnames, IPv4 and bracketed IPv6 literals (optional port) and POSIX user
    /// names reach a command or a connection.
    #[test]
    fn hostile_node_fields_are_refused() {
        for host in [
            "10.0.0.1",
            "node-1.example.com",
            "127.0.0.1:2222",
            "localhost",
            "[::1]:22",
            "[2001:db8::1]",
        ] {
            assert!(valid_host(host), "{host} must be accepted");
        }
        for host in [
            "a;touch /tmp/x",
            "$(id)",
            "a b",
            "a\nb",
            "'x",
            "host:",
            "host:0",
            "host:99999",
            "-a.example",
            "",
            "a..b",
            "`id`",
            "a|b",
            "::1",
        ] {
            assert!(!valid_host(host), "{host:?} must be refused");
        }
        for user in ["root", "deploy_user", "_svc", "a.b-c"] {
            assert!(valid_user(user), "{user} must be accepted");
        }
        for user in ["", "-x", "a b", "x;y", "a\nb", "$(id)"] {
            assert!(!valid_user(user), "{user:?} must be refused");
        }
        let mut nodes = vec![node("10.0.0.1", "primary"), node("10.0.0.2", "standby")];
        assert_eq!(validate(&nodes), Ok(()));
        nodes[1].host = "10.0.0.2;reboot".into();
        assert_eq!(validate(&nodes), Err("invalid node host"));
        nodes[1].host = "10.0.0.2".into();
        nodes[1].ssh_user = "root; id".into();
        assert_eq!(validate(&nodes), Err("invalid ssh_user"));
    }
    /// Defence in depth: the command builder itself refuses a hostile host and single-quotes
    /// anything with shell syntax, so even a validated IPv6 literal is one shell word.
    #[test]
    fn commands_never_carry_an_unquoted_node_host() {
        let config = Config::fixed(String::new(), "a".repeat(64), ("a".into(), "b".into()));
        let hostile = vec![
            node("10.0.0.1;id", "primary"),
            node("10.0.0.2", "standby"),
            node("10.0.0.3", "standby"),
        ];
        assert!(commands::build(2, &hostile, &config).is_err());
        let nodes = vec![
            node("[::1]:2222", "primary"),
            node("10.0.0.2", "standby"),
            node("10.0.0.3", "standby"),
        ];
        let jobs = commands::build(2, &nodes, &config).expect("replication commands");
        assert!(
            jobs.iter()
                .any(|j| j.command.contains("pg_basebackup -h '[::1]:2222' ")),
            "the primary host must be one quoted shell word"
        );
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
        assert_eq!(sh_quote("10.0.0.1:22"), "10.0.0.1:22");
    }
}
