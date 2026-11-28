//! Independent network peers for the frozen-Go enabled-pipeline recording.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

pub struct Peers {
    pub config: setjoin_smtp::inbound::Config,
    events: Arc<Mutex<Vec<Value>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Peers {
    pub async fn start(case: &Value) -> Self {
        let p = &case["pipeline"];
        let strings = |key: &str| {
            p[key]
                .as_array()
                .map(|a| a.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
                .unwrap_or_default()
        };
        let config = setjoin_smtp::inbound::Config {
            anti_phish: p["anti_phish"] == true,
            internal_domains: strings("internal_domains"),
            protected_domains: strings("protected_domains"),
            name_threshold: p["name_threshold"].as_f64().unwrap_or(0.85),
            ..Default::default()
        };
        let mut peers = Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            tasks: Vec::new(),
        };
        if let Some(secret) = p["link_secret"].as_str().filter(|s| !s.is_empty()) {
            peers.config.links = Some(setjoin_smtp::inbound::LinkConfig {
                key: setjoin_smtp::inbound::derive_link_key(
                    secret.as_bytes(),
                    p["link_version"].as_i64().unwrap_or(0).max(1),
                ),
                version: p["link_version"].as_i64().unwrap_or(0),
                clock_unix: recorded_link_clock(case),
            });
        }
        if let Some(reply) = p["clam_reply"].as_str().filter(|s| !s.is_empty()) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            peers.config.clamav_addr = Some(listener.local_addr().unwrap().to_string());
            if reply == "unavailable" {
                drop(listener);
            } else {
                let reply = reply.to_owned();
                let ping = p["clam_ping_reply"].as_str().unwrap_or("PONG").to_owned();
                let close = p["clam_close"] == true;
                let events = peers.events.clone();
                peers.tasks.push(tokio::spawn(async move {
                let mut jobs=tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted=listener.accept()=>{
                            let (socket,_)=accepted.unwrap();let events=events.clone();let reply=reply.clone();let ping=ping.clone();
                            jobs.spawn(async move{
                                let mut socket=BufReader::new(socket);
                                loop {
                                    let mut command=String::new();
                                    if socket.read_line(&mut command).await.unwrap_or(0)==0{return;}
                                    let mut event=json!({"kind":"clamav","command":command});
                                    let response=if command=="nINSTREAM\n"{
                                        let mut raw=Vec::new();
                                        loop{let Ok(size)=socket.read_u32().await else{return;};if size==0{break;}assert!(size<=4096);let start=raw.len();raw.resize(start+size as usize,0);if socket.read_exact(&mut raw[start..]).await.is_err(){return;}}
                                        event["length"]=json!(raw.len());event["sha256"]=json!(format!("{:x}",Sha256::digest(&raw)));reply.clone()
                                    }else{assert_eq!(command,"nPING\n");ping.clone()};
                                    events.lock().unwrap().push(event);
                                    if reply=="eof"&&command=="nINSTREAM\n"{return;}
                                    if socket.get_mut().write_all(format!("{response}\n").as_bytes()).await.is_err(){return;}
                                    if close{return;}
                                }
                            });
                        },
                        finished=jobs.join_next(),if !jobs.is_empty()=>{finished.unwrap().unwrap();},
                    }
                }
            }));
            }
        }
        if p["cape"] == true {
            use http_body_util::{BodyExt, Full};
            use hyper::{body::Bytes, service::service_fn, Response};
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            peers.config.sandbox = Some(setjoin_smtp::inbound::SandboxConfig {
                url: format!("http://{}", listener.local_addr().unwrap()),
                api_key: "smtp6-cape-key".into(),
                timeout: std::time::Duration::from_millis(
                    p["cape_timeout_ms"]
                        .as_u64()
                        .filter(|n| *n > 0)
                        .unwrap_or(10000),
                ),
                fail_closed: p["cape_fail_mode"] == "closed",
            });
            let events = peers.events.clone();
            let p = p.clone();
            peers.tasks.push(tokio::spawn(async move {
                let mut jobs=tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted=listener.accept()=>{
                            let(socket,_)=accepted.unwrap();let events=events.clone();let p=p.clone();
                            jobs.spawn(async move {
                                let service=service_fn(move |request:hyper::Request<hyper::body::Incoming>|{
                                    let events=events.clone();let p=p.clone();
                                    async move {
                                        let path=request.uri().path().to_owned();
                                        let mut event=json!({"kind":"cape","method":request.method().as_str(),"path":path,"authorization":request.headers().get("authorization").unwrap().to_str().unwrap()});
                                        let mut status=200;let mut body=json!({"ok":true}).to_string();
                                        if path=="/apiv2/tasks/create/file/" {
                                            let boundary=multer::parse_boundary(request.headers().get("content-type").unwrap().to_str().unwrap()).unwrap();
                                            let bytes=request.into_body().collect().await.unwrap().to_bytes();
                                            let stream=futures_util::stream::once(async move{Ok::<_,std::io::Error>(bytes)});
                                            let mut multipart=multer::Multipart::new(stream,boundary);
                                            let field=multipart.next_field().await.unwrap().unwrap();
                                            assert_eq!(field.name(),Some("file"));
                                            event["filename"]=json!(field.file_name().unwrap());
                                            let bytes=field.bytes().await.unwrap();
                                            event["length"]=json!(bytes.len());event["sha256"]=json!(format!("{:x}",Sha256::digest(&bytes)));
                                            assert!(multipart.next_field().await.unwrap().is_none());
                                            status=p["cape_submit_status"].as_u64().filter(|n|*n>0).unwrap_or(200) as u16;
                                            body=json!({"task_id":if p["cape_zero_id"]==true{0}else{42}}).to_string();
                                        }else if path=="/apiv2/tasks/view/42" {
                                            status=p["cape_view_status"].as_u64().filter(|n|*n>0).unwrap_or(200) as u16;
                                            body=if p["cape_malformed"]==true {"not-json".into()}else{json!({"task":{"id":42,"status":p["cape_status"].as_str().filter(|s|!s.is_empty()).unwrap_or("reported")},"info":{"score":p["cape_score"].as_f64().unwrap_or(0.0),"signatures":["first",p["cape_family"].as_str().filter(|s|!s.is_empty()).unwrap_or("CAPE.Test")]}}).to_string()};
                                        }else{assert_eq!(path,"/apiv2/tasks/status/health/");}
                                        events.lock().unwrap().push(event);
                                        Ok::<_,std::convert::Infallible>(Response::builder().status(status).header("content-type","application/json").body(Full::new(Bytes::from(body))).unwrap())
                                    }
                                });
                                hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(socket),service).await.unwrap();
                            });
                        },
                        finished=jobs.join_next(),if !jobs.is_empty()=>{finished.unwrap().unwrap();},
                    }
                }
            }));
        }
        peers
    }
    pub fn observed(&self) -> Value {
        json!(*self.events.lock().unwrap())
    }
    pub async fn finish(self) {
        for task in self.tasks {
            task.abort();
            if let Err(e) = task.await {
                if e.is_panic() {
                    std::panic::resume_unwind(e.into_panic());
                }
            }
        }
    }
}

// A warning can put the original Message-ID into the body, so the recorder's
// normal-header clock observation is absent. The immutable Go raw blob still
// carries the real minted token: recover only its time, never its signature or
// expected body. The production rewriter must independently reproduce all bytes.
fn recorded_link_clock(case: &Value) -> Option<i64> {
    use base64::Engine as _;
    if let Some(clock) = case["pipeline"]["link_clock"].as_i64() {
        return Some(clock);
    }
    static TOKEN: std::sync::LazyLock<regex::bytes::Regex> = std::sync::LazyLock::new(|| {
        regex::bytes::Regex::new(r"/link-protect\?token=([A-Za-z0-9_\-=]+)\.[A-Za-z0-9_\-=]+")
            .unwrap()
    });
    for packed in case["blobs"].as_object()?.values() {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(packed.as_str()?)
            .ok()?;
        for token in TOKEN.captures_iter(&raw) {
            let Ok(payload) = base64::engine::general_purpose::URL_SAFE.decode(&token[1]) else {
                continue;
            };
            let Ok(claims) = serde_json::from_slice::<Value>(&payload) else {
                continue;
            };
            if let Some(expires) = claims["e"].as_i64() {
                return expires.checked_sub(30 * 24 * 60 * 60);
            }
        }
    }
    None
}
