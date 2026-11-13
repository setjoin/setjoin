//! Actual python-caldav discovery and CRUD captures. Ordinary replay consumes
//! the immutable HTTP transcript; Python is recording tooling only.
use super::{common, fixture, golden, snapshot, BoxError, Db};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct Bindings {
    ids: Vec<(i64, String)>,
    etags: Vec<(String, String)>,
    domains: Vec<(String, String)>,
}
impl Bindings {
    async fn learn(&mut self, c: &tokio_postgres::Client, a: i64, b: i64) -> Result<(), BoxError> {
        for row in c.query("SELECT ce.id,ce.uid,ce.etag FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id WHERE c.mailbox_id IN ($1,$2) ORDER BY ce.id",&[&a,&b]).await? {
            let id:i64=row.get(0);let uid:String=row.get(1);let etag:String=row.get(2);
            if !self.ids.iter().any(|(known,_)|*known==id) {self.ids.push((id,format!("<event:{uid}>")));}
            if !self.etags.iter().any(|(known,_)|*known==etag) {
                let prefix=format!("<etag:{uid}:");let version=self.etags.iter().filter(|(_,label)|label.starts_with(&prefix)).count();
                self.etags.push((etag,format!("<etag:{uid}:{version}>")));
            }
        }
        Ok(())
    }
    fn text(&self, value: &str) -> String {
        let mut value = value.to_owned();
        for (raw, label) in self.domains.iter().chain(self.etags.iter()) {
            value = value.replace(raw, label);
        }
        let mut out = String::new();
        let mut chars = value.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch.is_ascii_digit() {
                let mut digits = String::from(ch);
                while chars.peek().is_some_and(char::is_ascii_digit) {
                    digits.push(chars.next().unwrap());
                }
                if let Some((_, label)) = digits
                    .parse::<i64>()
                    .ok()
                    .and_then(|id| self.ids.iter().find(|(known, _)| *known == id))
                {
                    out.push_str(label);
                } else {
                    out.push_str(&digits);
                }
            } else {
                out.push(ch);
            }
        }
        out
    }
    fn retarget(&self, value: &str) -> String {
        let mut value = value.to_owned();
        for (id, label) in &self.ids {
            value = value.replace(label, &id.to_string());
        }
        for (raw, label) in &self.etags {
            value = value.replace(label, raw);
        }
        value
    }
    fn value(&self, value: &mut Value) {
        match value {
            Value::String(s) => *s = self.text(s),
            Value::Number(n) => {
                if let Some((_, label)) = n
                    .as_i64()
                    .and_then(|id| self.ids.iter().find(|(known, _)| *known == id))
                {
                    *value = json!(label);
                }
            }
            Value::Array(xs) => {
                for value in xs {
                    self.value(value);
                }
            }
            Value::Object(m) => {
                for value in m.values_mut() {
                    self.value(value);
                }
            }
            _ => {}
        }
    }
}
fn ledger(line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}
fn normalize_traffic(value: &mut Value, bindings: &Bindings) -> Result<(), BoxError> {
    let stamp = regex::Regex::new(r"DTSTAMP:\d{8}T\d{6}Z")?;
    for entry in value.as_array_mut().ok_or("client traffic array")? {
        let raw = entry["response"]["body"]
            .as_str()
            .ok_or("client response body")?
            .to_owned();
        if let Some(length) = entry["response"]["headers"].get("content-length") {
            if length[0] != raw.len().to_string() {
                return Err("client wire content-length mismatch".into());
            }
        }
        bindings.value(entry);
        let body = entry["response"]["body"].as_str().unwrap();
        entry["response"]["body"] =
            json!(stamp.replace_all(body, "DTSTAMP:<timestamp>").into_owned());
        if entry["response"]["headers"].get("date").is_some() {
            entry["response"]["headers"]["date"] = json!(["<timestamp>"]);
        }
        if entry["response"]["headers"].get("content-length").is_some() {
            entry["response"]["headers"]["content-length"] = json!([entry["response"]["body"]
                .as_str()
                .unwrap()
                .len()
                .to_string()]);
        }
    }
    Ok(())
}

pub async fn drive(
    db: &Db,
    owner: Arc<tokio_postgres::Client>,
    a: &fixture::Account,
    b: &fixture::Account,
    address: SocketAddr,
    token: &str,
    recording: bool,
) -> Result<(), BoxError> {
    let mut bindings = Bindings {
        ids: vec![
            (a.user, "<user-a>".into()),
            (b.user, "<user-b>".into()),
            (a.mailbox, "<mailbox-a>".into()),
            (b.mailbox, "<mailbox-b>".into()),
        ],
        ..Bindings::default()
    };
    for (domain, label) in [(a.domain, "a.test"), (b.domain, "b.test")] {
        bindings.domains.push((
            owner
                .query_one("SELECT name FROM domains WHERE id=$1", &[&domain])
                .await?
                .get(0),
            label.into(),
        ));
    }
    let bindings = Arc::new(Mutex::new(bindings));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let (ma, mb) = (a.mailbox, b.mailbox);
    let before = snapshot(&owner, ma, mb, true).await?;
    let mut notices_a = db.listen(&format!("calendar:{ma}")).await?;
    let mut notices_b = db.listen(&format!("calendar:{mb}")).await?;
    let observer = common::fake_upstream({
        let owner = owner.clone();
        let bindings = bindings.clone();
        let errors = errors.clone();
        move |request| {
            let owner = owner.clone();
            let bindings = bindings.clone();
            let errors = errors.clone();
            async move {
                let observed = async {
                    let (parts, body) = request.into_parts();
                    let bytes = body.collect().await?.to_bytes();
                    let mut target = Request::builder()
                        .method(parts.method)
                        .uri(parts.uri.path_and_query().map_or("/", |p| p.as_str()))
                        .body(common::full(bytes))?;
                    *target.headers_mut() = parts.headers;
                    let response = common::send(address, target).await;
                    let status = response.status();
                    let headers = response.headers().clone();
                    let bytes = common::body_bytes(response).await;
                    bindings.lock().await.learn(&owner, ma, mb).await?;
                    let mut response = Response::new(common::full(bytes));
                    *response.status_mut() = status;
                    *response.headers_mut() = headers;
                    Ok::<_, BoxError>(response)
                }
                .await;
                match observed {
                    Ok(response) => response,
                    Err(error) => {
                        errors.lock().await.push(error.to_string());
                        Response::builder()
                            .status(500)
                            .body(common::full("capture failed"))
                            .unwrap()
                    }
                }
            }
        }
    })
    .await;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let file =
        root.join("server-rust/tests/conformance/caldav/goldens/python-client-sessions.json");
    let expected = if recording {
        None
    } else {
        Some(serde_json::from_slice::<Value>(&std::fs::read(&file)?)?)
    };
    let mut capture = if recording {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = root.join(format!(
            "test-results/gofree-cal4/gofree-cal4-client-{unique}.json"
        ));
        ledger(&format!(
            "Planned Python caldav capture {} (two real sessions, own fixture/front door only)",
            path.display()
        ))?;
        let python = std::env::var_os("GOFREE_CALDAV_PYTHON")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("test-results/gofree-cal4/python/bin/python"));
        let child = tokio::process::Command::new(python)
            .arg(root.join("server-rust/tests/conformance/caldav/record-client.py"))
            .arg(format!("http://{observer}"))
            .arg(token)
            .arg(&path)
            .kill_on_drop(true)
            .spawn()?;
        ledger(&format!(
            "Started owned python-caldav child PID {:?}",
            child.id()
        ))?;
        let status =
            tokio::time::timeout(std::time::Duration::from_secs(60), child.wait_with_output())
                .await??;
        if !status.status.success() {
            return Err("python-caldav capture failed".into());
        }
        ledger("Python caldav capture child reaped")?;
        let capture = serde_json::from_slice::<Value>(&std::fs::read(&path)?)?;
        capture
    } else {
        let original = &expected.as_ref().unwrap()["observation"]["client"];
        let mut traffic = Vec::new();
        for entry in original["traffic"]
            .as_array()
            .ok_or("recorded client traffic")?
        {
            let current = bindings.lock().await.clone();
            let path = current.retarget(entry["path"].as_str().ok_or("client path")?);
            let query = current.retarget(entry["query"].as_str().unwrap_or(""));
            let uri = if query.is_empty() {
                path
            } else {
                format!("{path}?{query}")
            };
            let method = entry["method"].as_str().ok_or("client method")?;
            let body = current.retarget(entry["body"].as_str().unwrap_or(""));
            let mut request = Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "mail.test")
                .header("authorization", format!("Bearer {token}"));
            for (name, value) in entry["headers"].as_object().ok_or("client headers")? {
                request = request.header(
                    name,
                    current.retarget(value.as_str().ok_or("client header")?),
                );
            }
            let response = common::send(observer, request.body(common::full(body))?).await;
            let response = super::observe_response(response).await?;
            let mut actual = entry.clone();
            actual["response"] = response;
            traffic.push(actual);
        }
        let mut capture = original.clone();
        capture["traffic"] = json!(traffic);
        capture
    };
    if !errors.lock().await.is_empty() {
        return Err(format!("client observer failed: {:?}", *errors.lock().await).into());
    }
    let traffic = capture["traffic"]
        .as_array()
        .ok_or("empty client capture")?;
    for method in ["PROPFIND", "PUT", "GET", "REPORT", "DELETE"] {
        if !traffic.iter().any(|e| e["method"] == method) {
            return Err(format!("real client did not exercise {method}").into());
        }
    }
    let mut notify = vec![];
    for (name, listener) in [("a", &mut notices_a), ("b", &mut notices_b)] {
        for value in listener.drain(&owner).await? {
            notify.push(json!({"mailbox":name,"payload":serde_json::from_str::<Value>(&value)?}));
        }
    }
    let after = snapshot(&owner, ma, mb, true).await?;
    let current = bindings.lock().await.clone();
    normalize_traffic(&mut capture["traffic"], &current)?;
    let mut observation = json!({"client":capture,"effects":[{"table":"f17-caldav","before":before,"after":after}],"notify":notify});
    current.value(&mut observation["effects"]);
    current.value(&mut observation["notify"]);
    if recording {
        golden::record(
            &file,
            &json!({"format":1,"route":"* /caldav/ client-session","case":"python-caldav","go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        golden::compare(&expected.unwrap()["observation"], &observation)?;
        let response = common::send(
            address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if !body
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_total 0")
        {
            return Err(format!("real client forwarded requests: {body}").into());
        }
        eprintln!("GOLDEN-REPLAY: * /caldav/ client-session :: python-caldav (two real recorded sessions)");
    }
    Ok(())
}

/// Boot the production route table with real shared admission and no Go mail upstream.
pub(super) async fn executable(
    address: SocketAddr,
    app: &str,
) -> Result<common::boot::Child, BoxError> {
    use common::boot::CommandBootExt;
    use std::process::{Command, Stdio};
    let jwks = common::fake_upstream(|_| async {
        Response::new(common::full(include_str!(
            "../../../../tests/conformance/jmap/test-jwks.json"
        )))
    })
    .await;
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .env_clear()
        .env("GATEWAY_LISTEN", address.to_string())
        .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
        .env("AUTHSERVER_JWKS_URL", format!("http://{jwks}/jwks"))
        .env("DB_DSN", app)
        .env("DB_DIRECT_DSN", std::env::var("DB_DIRECT_DSN")?)
        .env("GATEWAY_DB_POOL", "4")
        .env("CORE_RATE_LIMIT", "100000")
        .env("SETJOIN_PG_DEADLINE_MS", "30000")
        .env("SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS", "30000")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = command.spawn_boot()?;
    ledger(&format!(
        "gofree-cal4 production gateway pid={} started",
        child.id()
    ))?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("production gateway exited: {status}").into());
        }
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            return Err("production gateway never listened".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(child)
}
