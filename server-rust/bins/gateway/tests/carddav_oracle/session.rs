//! Actual vdirsyncer capture and permanent HTTP transcript replay.
use super::{common, fixture, golden, normalize, snapshot, BoxError, Db};
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
        for row in c.query("SELECT c.id,c.vcard_uid,c.etag FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id WHERE ab.mailbox_id IN ($1,$2) ORDER BY c.id",&[&a,&b]).await? {
            let id:i64=row.get(0);let uid:String=row.get(1);let etag:String=row.get(2);
            if !self.ids.iter().any(|(known,_)|*known==id){self.ids.push((id,format!("<contact:{uid}>")));}
            if !self.etags.iter().any(|(known,_)|known==&etag){let prefix=format!("<etag:{uid}:");let version=self.etags.iter().filter(|(_,name)|name.starts_with(&prefix)).count();self.etags.push((etag,format!("{prefix}{version}>")));}
        }
        Ok(())
    }
    fn value(&self, value: &mut Value) {
        let replacements = self
            .domains
            .iter()
            .chain(self.etags.iter())
            .map(|(raw, label)| (raw.clone(), label.as_str()))
            .collect::<Vec<_>>();
        normalize(value, &self.ids, &replacements);
    }
    fn retarget(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for (id, label) in &self.ids {
            text = text.replace(label, &id.to_string());
        }
        for (raw, label) in self.etags.iter().chain(self.domains.iter()) {
            text = text.replace(label, raw);
        }
        text
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
fn response(status: u16, headers: &hyper::HeaderMap, body: &[u8]) -> Result<Value, BoxError> {
    let mut fields = serde_json::Map::new();
    for key in headers.keys() {
        fields.insert(
            key.to_string(),
            json!(headers
                .get_all(key)
                .iter()
                .map(|v| v.to_str().map(str::to_owned))
                .collect::<Result<Vec<_>, _>>()?),
        );
    }
    if fields
        .get("content-length")
        .is_some_and(|v| v[0] != body.len().to_string())
    {
        return Err("client wire Content-Length mismatch".into());
    }
    Ok(json!({"status":status,"headers":fields,"body":String::from_utf8(body.to_vec())?}))
}
fn normalize_entry(entry: &mut Value, bindings: &Bindings) -> Result<(), BoxError> {
    bindings.value(entry);
    let body = entry["response"]["body"]
        .as_str()
        .ok_or("client response body")?;
    let pattern = regex::Regex::new(r"REV:\d{8}T\d{6}Z")?;
    let body = pattern.replace_all(body, "REV:<timestamp>").into_owned();
    let length = body.len().to_string();
    entry["response"]["body"] = json!(body);
    if entry["response"]["headers"].get("date").is_some() {
        entry["response"]["headers"]["date"] = json!(["<timestamp>"]);
    }
    if entry["response"]["headers"].get("content-length").is_some() {
        entry["response"]["headers"]["content-length"] = json!([length]);
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
    let mut initial = Bindings {
        ids: vec![
            (a.user, "<user-a>".into()),
            (b.user, "<user-b>".into()),
            (a.mailbox, "<mailbox-a>".into()),
            (b.mailbox, "<mailbox-b>".into()),
        ],
        ..Bindings::default()
    };
    for (id, label) in [(a.domain, 'a'), (b.domain, 'b')] {
        let domain: String = owner
            .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
            .await?
            .get(0);
        initial.domains.push((
            domain,
            format!("oracle-{}.test", label.to_string().repeat(32)),
        ));
    }
    initial.learn(&owner, a.mailbox, b.mailbox).await?;
    let bindings = Arc::new(Mutex::new(initial));
    let traffic = Arc::new(Mutex::new(Vec::<Value>::new()));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let before = snapshot(&owner, a.mailbox, b.mailbox).await?;
    let mut na = db.listen(&format!("contact:{}", a.mailbox)).await?;
    let mut nb = db.listen(&format!("contact:{}", b.mailbox)).await?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let file = root.join("server-rust/tests/conformance/carddav/goldens/vdirsyncer-sessions.json");
    let expected = if recording {
        None
    } else {
        Some(serde_json::from_slice::<Value>(&std::fs::read(&file)?)?)
    };
    let capture = if recording {
        let observer=common::fake_upstream({
            let (owner,bindings,traffic,errors)=(owner.clone(),bindings.clone(),traffic.clone(),errors.clone());let (ma,mb)=(a.mailbox,b.mailbox);
            move |request|{let (owner,bindings,traffic,errors)=(owner.clone(),bindings.clone(),traffic.clone(),errors.clone());async move{
                let observed=async {
                    let (parts,body)=request.into_parts();let bytes=body.collect().await?.to_bytes();
                    let mut headers=serde_json::Map::new();for key in parts.headers.keys(){if !matches!(key.as_str(),"authorization"|"host"|"content-length"|"connection"|"accept-encoding"){headers.insert(key.to_string(),json!(parts.headers.get(key).ok_or("header")?.to_str()?));}}
                    let mut entry=json!({"method":parts.method.as_str(),"path":parts.uri.path(),"query":parts.uri.query().unwrap_or(""),"headers":headers,"body":String::from_utf8(bytes.to_vec())?});
                    let mut request=Request::builder().method(parts.method).uri(parts.uri.path_and_query().map_or("/",|u|u.as_str())).body(common::full(bytes))?;*request.headers_mut()=parts.headers;
                    let received=common::send(address,request).await;let status=received.status();let headers=received.headers().clone();let bytes=common::body_bytes(received).await;
                    entry["response"]=response(status.as_u16(),&headers,&bytes)?;
                    let mut current=bindings.lock().await;current.learn(&owner,ma,mb).await?;normalize_entry(&mut entry,&current)?;drop(current);
                    traffic.lock().await.push(entry);
                    let mut reply=Response::new(common::full(bytes));*reply.status_mut()=status;*reply.headers_mut()=headers;Ok::<_,BoxError>(reply)
                }.await;
                match observed{Ok(reply)=>reply,Err(error)=>{errors.lock().await.push(error.to_string());Response::builder().status(500).body(common::full("client observer failed")).unwrap()}}
            }}
        }).await;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = root.join(format!(
            "test-results/gofree-cal5/gofree-cal5-client-{stamp}.json"
        ));
        ledger(&format!(
            "Planned vdirsyncer child and outcomes {} (only owned fixture/front door)",
            path.display()
        ))?;
        let python = std::env::var_os("GOFREE_CARDDAV_PYTHON")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("test-results/gofree-cal5/python/bin/python"));
        let child = tokio::process::Command::new(python)
            .arg(root.join("server-rust/tests/conformance/carddav/record-client.py"))
            .arg(format!("http://{observer}"))
            .arg(token)
            .arg(&path)
            .kill_on_drop(true)
            .spawn()?;
        ledger(&format!(
            "gofree-cal5 vdirsyncer child pid={:?} started",
            child.id()
        ))?;
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(60), child.wait_with_output())
                .await??;
        if !output.status.success() {
            return Err("actual vdirsyncer session failed".into());
        }
        ledger("gofree-cal5 vdirsyncer child reaped")?;
        let mut capture = serde_json::from_slice::<Value>(&std::fs::read(path)?)?;
        capture["traffic"] = json!(traffic.lock().await.clone());
        capture
    } else {
        let original =
            &expected.as_ref().ok_or("expected client capture")?["observation"]["client"];
        for entry in original["traffic"].as_array().ok_or("client traffic")? {
            let current = bindings.lock().await.clone();
            let path = current.retarget(entry["path"].as_str().ok_or("client path")?);
            let query = current.retarget(entry["query"].as_str().unwrap_or(""));
            let uri = if query.is_empty() {
                path
            } else {
                format!("{path}?{query}")
            };
            let mut request = Request::builder()
                .method(entry["method"].as_str().ok_or("client method")?)
                .uri(uri)
                .header("host", "mail.test")
                .header("authorization", format!("Bearer {token}"));
            for (key, value) in entry["headers"].as_object().ok_or("client headers")? {
                request = request.header(
                    key,
                    current.retarget(value.as_str().ok_or("client header value")?),
                );
            }
            let reply = common::send(
                address,
                request.body(common::full(
                    current.retarget(entry["body"].as_str().ok_or("client body")?),
                ))?,
            )
            .await;
            let status = reply.status().as_u16();
            let headers = reply.headers().clone();
            let body = common::body_bytes(reply).await;
            let mut observed = entry.clone();
            observed["response"] = response(status, &headers, &body)?;
            let mut current = bindings.lock().await;
            current.learn(&owner, a.mailbox, b.mailbox).await?;
            normalize_entry(&mut observed, &current)?;
            drop(current);
            traffic.lock().await.push(observed);
        }
        let mut capture = original.clone();
        capture["traffic"] = json!(traffic.lock().await.clone());
        capture
    };
    if !errors.lock().await.is_empty() {
        return Err(format!("client observer errors: {:?}", *errors.lock().await).into());
    }
    for method in ["PROPFIND", "REPORT", "PUT", "DELETE"] {
        if !capture["traffic"]
            .as_array()
            .ok_or("client traffic array")?
            .iter()
            .any(|entry| entry["method"] == method)
        {
            return Err(format!("actual client did not exercise {method}").into());
        }
    }
    let mut notify = vec![];
    for (name, listener) in [("a", &mut na), ("b", &mut nb)] {
        for payload in listener.drain(&owner).await? {
            notify.push(json!({"mailbox":name,"payload":serde_json::from_str::<Value>(&payload)?}));
        }
    }
    let after = snapshot(&owner, a.mailbox, b.mailbox).await?;
    let current = bindings.lock().await.clone();
    let mut observation = json!({"client":capture,"effects":[{"table":"f17-carddav","before":before,"after":after}],"audit":[],"notify":notify});
    current.value(&mut observation["effects"]);
    current.value(&mut observation["notify"]);
    if recording {
        golden::record(
            &file,
            &json!({"format":1,"route":"* /carddav/ client-session","case":"vdirsyncer","go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        golden::compare(
            &expected.ok_or("expected session")?["observation"],
            &observation,
        )?;
        let metrics = common::send(
            address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        if !metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_total 0")
        {
            return Err(format!("client session forwarded: {metrics}").into());
        }
        eprintln!("GOLDEN-REPLAY: * /carddav/ client-session :: vdirsyncer (actual discovery, vCard3/4 CRUD and GAL)");
    }
    Ok(())
}

/// Boot the production route table with real shared admission and no Go mail upstream.
pub(super) async fn executable(
    address: SocketAddr,
    app: &str,
) -> Result<common::boot::Child, BoxError> {
    use common::boot::CommandBootExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let jwks = common::fake_upstream(|_| async {
        Response::new(common::full(include_str!(
            "../../../../tests/conformance/jmap/test-jwks.json"
        )))
    })
    .await;
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .arg0("gofree-cal5-gateway")
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
        "gofree-cal5 production gateway pid={} started",
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
