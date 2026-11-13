//! #410: the `meet-reconcile` worker, one seed plus one tick per case.
//! Recording runs the frozen Go server with only `meet-reconcile` left on
//! (`GOFREE_ORACLE_KEEP_WORKERS`; its first tick lands 60 s after launch)
//! against fake LiveKit twirp, Egress, ASR-bot and S3 peers; replay seeds the
//! same rows and runs ONE tick of the Rust worker against the same peers. A
//! case observes the database (ids and times masked), the `meet:<user>`
//! notifications, every twirp/ASR call (grant included) and every object
//! mutation. Go is the oracle (ARCH-029).
mod common;
#[path = "common/meet_fixture.rs"]
mod meet_fixture;
#[path = "common/meet_peripherals.rs"]
mod meet_peripherals;
use common::BoxError;
use http_body_util::BodyExt;
use hyper::Response;
use meet_peripherals::{verify, KEY, SECRET};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    meet_livekit::LiveKit, meet_worker::MeetReconcile, recovery_worker::S3Store,
};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const BUCKET: &str = "mailblobs";
const ASR_TOKEN: &str = "meet5-asr";

macro_rules! cases {
    ($($name:ident = $case:literal;)*) => {$(
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            run($case, Mutant::None).await
        }
    )*};
}

cases! {
    lobby_expiry = "lobby-expiry";
    ended_room_delete = "ended-room-delete";
    breakout_room_gc = "breakout-room-gc";
    lost_webhook_gc = "lost-webhook-gc";
    lost_webhook_quiet = "lost-webhook-quiet";
    breakout_presence_heal = "breakout-presence-heal";
    breakout_absent_first_tick = "breakout-absent-first-tick";
    captions_crashed = "captions-crashed";
    captions_orphan = "captions-orphan";
    captions_grace = "captions-grace";
    recording_ended_residue = "recording-ended-residue";
    recording_stale_requested = "recording-stale-requested";
    recording_stop_retry = "recording-stop-retry";
    recording_vanished_failed = "recording-vanished-failed";
    recording_vanished_complete = "recording-vanished-complete";
    egress_belt = "egress-belt";
    egress_young = "egress-young";
    local_lease_expire = "local-lease-expire";
    feature_off = "feature-off";
    list_rooms_fails = "list-rooms-fails";
    semantic_sweep = "semantic-sweep";
    semantic_export = "semantic-export";
    drive_history = "drive-history";
    ingest_recording = "ingest-recording";
    ingest_success = "ingest-success";
    ingest_exhausted = "ingest-exhausted";
    reap_staging = "reap-staging";
}

#[derive(Clone, Copy, PartialEq)]
enum Mutant {
    None,
    /// The Rust worker believes LiveKit is not configured.
    Unconfigured,
}

#[tokio::test]
async fn planted_unconfigured_mutant_fails_the_golden() -> Result<(), BoxError> {
    let failure = run("ended-room-delete", Mutant::Unconfigured).await;
    assert!(
        failure.is_err(),
        "a worker that skips the live legs must not match the Go recording"
    );
    println!("MUTANT-REJECTED: meet-reconcile :: live legs skipped");
    Ok(())
}

// ---- peers ---------------------------------------------------------------

#[derive(Default)]
struct SfuState {
    rooms: Vec<String>,
    participants: HashMap<String, Vec<String>>,
    /// (egress id, status number, started_at unix ns)
    egress: Vec<(String, u8, i64)>,
    fail_list_rooms: bool,
    calls: Vec<Value>,
    asr_rooms: Vec<String>,
    asr_calls: Vec<Value>,
    objects: BTreeMap<String, (Vec<u8>, i64)>,
    s3_ops: Vec<Value>,
}
type Peers = Arc<Mutex<SfuState>>;

fn varint(b: &[u8], i: &mut usize) -> u64 {
    let (mut v, mut shift) = (0u64, 0);
    while *i < b.len() {
        let byte = b[*i];
        *i += 1;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    v
}
fn put_varint(mut n: u64, out: &mut Vec<u8>) {
    while n > 127 {
        out.push((n as u8) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn put_text(tag: u8, text: &str, out: &mut Vec<u8>) {
    out.push(tag);
    put_varint(text.len() as u64, out);
    out.extend_from_slice(text.as_bytes());
}
fn proto_fields(b: &[u8]) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let tag = varint(b, &mut i);
        match tag & 7 {
            0 => {
                let v = varint(b, &mut i);
                out.push((tag >> 3, v.to_string()));
            }
            2 => {
                let n = varint(b, &mut i) as usize;
                out.push((tag >> 3, String::from_utf8_lossy(&b[i..i + n]).into_owned()));
                i += n;
            }
            _ => break,
        }
    }
    out
}

async fn twirp(addr_state: Peers) -> SocketAddr {
    common::fake_upstream(move |req| {
        let state = addr_state.clone();
        async move {
            let path = req.uri().path().to_owned();
            let protobuf = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("protobuf"));
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::to_owned);
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let method = path.rsplit('/').next().unwrap_or("").to_owned();
            let grant = match auth.as_deref().and_then(|t| verify(t, SECRET)) {
                Some(c) => {
                    assert_eq!(c["iss"], KEY);
                    c["video"].clone()
                }
                None => json!("invalid-token"),
            };
            let mut decoded = serde_json::Map::new();
            if protobuf {
                for (field, value) in proto_fields(&body) {
                    let name = match (method.as_str(), field) {
                        ("DeleteRoom" | "ListParticipants", 1) => "room",
                        ("RemoveParticipant", 1) => "room",
                        ("RemoveParticipant", 2) => "identity",
                        ("StopEgress", 1) => "egressId",
                        _ => "unknown",
                    };
                    decoded.insert(name.into(), json!(value));
                }
            } else if let Ok(Value::Object(o)) = serde_json::from_slice::<Value>(&body) {
                decoded = o.into_iter().filter(|(_, v)| v != &json!("") && v != &json!(0)).collect();
            }
            let mut st = state.lock().unwrap();
            // Startup probes by the frozen process are discarded by the harness.
            st.calls.push(json!({"method":method,"grant":grant,"body":decoded}));
            if method == "ListRooms" && st.fail_list_rooms {
                return Response::builder()
                    .status(500)
                    .header("content-type", "application/json")
                    .body(common::full(json!({"code":"internal","msg":"injected"}).to_string()))
                    .unwrap();
            }
            let room = decoded.get("room").and_then(Value::as_str).unwrap_or("").to_owned();
            let (bytes, json_body): (Vec<u8>, Value) = match method.as_str() {
                "ListRooms" => {
                    let mut out = Vec::new();
                    for r in &st.rooms {
                        let mut room_msg = Vec::new();
                        put_text(0x12, r, &mut room_msg);
                        out.push(0x0a);
                        put_varint(room_msg.len() as u64, &mut out);
                        out.extend(room_msg);
                    }
                    (out, json!({"rooms": st.rooms.iter().map(|r| json!({"name":r})).collect::<Vec<_>>()}))
                }
                "ListParticipants" => {
                    let who = st.participants.get(&room).cloned().unwrap_or_default();
                    let mut out = Vec::new();
                    for id in &who {
                        let mut msg = Vec::new();
                        put_text(0x12, id, &mut msg);
                        out.push(0x0a);
                        put_varint(msg.len() as u64, &mut out);
                        out.extend(msg);
                    }
                    (out, json!({"participants": who.iter().map(|i| json!({"identity":i})).collect::<Vec<_>>()}))
                }
                "ListEgress" => {
                    let mut out = Vec::new();
                    let mut items = Vec::new();
                    for (id, status, started) in &st.egress {
                        let mut msg = Vec::new();
                        put_text(0x0a, id, &mut msg);
                        msg.push(0x18);
                        put_varint(u64::from(*status), &mut msg);
                        msg.push(0x50);
                        put_varint(*started as u64, &mut msg);
                        out.push(0x0a);
                        put_varint(msg.len() as u64, &mut out);
                        out.extend(msg);
                        let names = ["EGRESS_STARTING", "EGRESS_ACTIVE", "EGRESS_ENDING", "EGRESS_COMPLETE", "EGRESS_FAILED"];
                        items.push(json!({"egressId":id,"status":names[*status as usize],"startedAt":started.to_string()}));
                    }
                    (out, json!({"items": items}))
                }
                _ => (Vec::new(), json!({})),
            };
            if protobuf {
                Response::builder()
                    .header("content-type", "application/protobuf")
                    .body(common::full(bytes))
                    .unwrap()
            } else {
                Response::builder()
                    .header("content-type", "application/json")
                    .body(common::full(json_body.to_string()))
                    .unwrap()
            }
        }
    })
    .await
}

async fn asr(state: Peers) -> SocketAddr {
    common::fake_upstream(move |req| {
        let state = state.clone();
        async move {
            let (method, path) = (req.method().to_string(), req.uri().path().to_owned());
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    if v == format!("Bearer {ASR_TOKEN}") {
                        "Bearer <asr-token>".to_owned()
                    } else {
                        v.to_owned()
                    }
                });
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let mut st = state.lock().unwrap();
            if path == "/status" {
                return Response::builder()
                    .header("content-type", "application/json")
                    .body(common::full(json!({"rooms": st.asr_rooms}).to_string()))
                    .unwrap();
            }
            let decoded: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            st.asr_calls
                .push(json!({"method":method,"path":path,"authorization":auth,"body":decoded}));
            Response::builder()
                .header("content-type", "application/json")
                .body(common::full("{}"))
                .unwrap()
        }
    })
    .await
}

fn dechunk(mut framed: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(line_end) = framed.windows(2).position(|w| w == b"\r\n") {
        let header = String::from_utf8_lossy(&framed[..line_end]).into_owned();
        let size = usize::from_str_radix(header.split(';').next().unwrap_or("0"), 16).unwrap_or(0);
        framed = &framed[line_end + 2..];
        if size == 0 || framed.len() < size {
            break;
        }
        out.extend_from_slice(&framed[..size]);
        framed = framed.get(size + 2..).unwrap_or_default();
    }
    out
}

/// A path-style in-memory S3: location, list (v1/v2), head, ranged get, put,
/// copy and delete. Mutations are logged with their object key.
async fn s3(state: Peers) -> SocketAddr {
    common::fake_upstream(move |req| {
        let state = state.clone();
        async move {
            let (parts, body) = req.into_parts();
            let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let query = parts.uri.query().unwrap_or("").to_owned();
            let path = parts.uri.path().trim_start_matches('/').to_owned();
            let key = path.strip_prefix(&format!("{BUCKET}/")).unwrap_or("").to_owned();
            let key = String::from_utf8_lossy(&pct(&key)).into_owned();
            let xml = |status: u16, body: String| {
                Response::builder().status(status).header("content-type", "application/xml").body(common::full(body)).unwrap()
            };
            let mut st = state.lock().unwrap();
            if parts.method == hyper::Method::GET && query.starts_with("location") {
                return xml(200, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>".into());
            }
            if parts.method == hyper::Method::GET && key.is_empty() {
                let prefix = query
                    .split('&')
                    .find_map(|p| p.strip_prefix("prefix="))
                    .map(|p| String::from_utf8_lossy(&pct(p)).into_owned())
                    .unwrap_or_default();
                let mut items = String::new();
                for (k, (data, at)) in st.objects.iter().filter(|(k, _)| k.starts_with(&prefix)) {
                    let when = chrono::DateTime::from_timestamp(*at, 0).unwrap().format("%Y-%m-%dT%H:%M:%S.000Z");
                    items.push_str(&format!("<Contents><Key>{k}</Key><LastModified>{when}</LastModified><ETag>\"e\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>", data.len()));
                }
                return xml(200, format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{BUCKET}</Name><Prefix>{prefix}</Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>{items}</ListBucketResult>"));
            }
            match parts.method.as_str() {
                "HEAD" | "GET" => match st.objects.get(&key) {
                    None => xml(404, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>".into()),
                    Some((data, at)) => {
                        let mut slice = data.clone();
                        let mut status = 200;
                        if let Some(r) = parts.headers.get("range").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("bytes=")) {
                            let (a, b) = r.split_once('-').unwrap_or(("0", ""));
                            let a: usize = a.parse().unwrap_or(0);
                            let b: usize = b.parse().unwrap_or(data.len() - 1).min(data.len() - 1);
                            slice = data[a..=b].to_vec();
                            status = 206;
                        }
                        let when = chrono::DateTime::from_timestamp(*at, 0).unwrap().to_rfc2822().replace("+0000", "GMT");
                        let b = Response::builder()
                            .status(status)
                            .header("content-length", slice.len().to_string())
                            .header("last-modified", when)
                            .header("etag", "\"e\"");
                        if parts.method == hyper::Method::HEAD {
                            b.body(common::full("")).unwrap()
                        } else {
                            b.body(common::full(slice)).unwrap()
                        }
                    }
                },
                "PUT" if key.is_empty() => Response::builder().body(common::full("")).unwrap(),
                "PUT" => {
                    if let Some(src) = parts.headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok()) {
                        let src = String::from_utf8_lossy(&pct(src.trim_start_matches('/'))).into_owned();
                        let src = src.strip_prefix(&format!("{BUCKET}/")).unwrap_or(&src).to_owned();
                        let Some((data, _)) = st.objects.get(&src).cloned() else {
                            return xml(404, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>missing</Message></Error>".into());
                        };
                        st.s3_ops.push(json!({"op":"COPY","from":src,"to":key}));
                        st.objects.insert(key, (data, now()));
                        return xml(200, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyObjectResult><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>\"e\"</ETag></CopyObjectResult>".into());
                    }
                    let streaming = parts.headers.get("x-amz-content-sha256").is_some_and(|v| v == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
                    let data = if streaming { dechunk(&bytes) } else { bytes.to_vec() };
                    st.s3_ops.push(json!({"op":"PUT","key":key,"size":data.len()}));
                    st.objects.insert(key, (data, now()));
                    Response::builder().header("etag", "\"e\"").body(common::full("")).unwrap()
                }
                "DELETE" => {
                    st.s3_ops.push(json!({"op":"DELETE","key":key}));
                    st.objects.remove(&key);
                    Response::builder().status(204).body(common::full("")).unwrap()
                }
                _ => xml(405, "<Error><Code>MethodNotAllowed</Code></Error>".into()),
            }
        }
    })
    .await
}

/// Replaces `needle` only where it is not followed by another digit.
fn replace_token(s: &str, needle: &str, with: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find(needle) {
        let after = &rest[at + needle.len()..];
        out.push_str(&rest[..at]);
        if after.starts_with(|c: char| c.is_ascii_digit()) {
            out.push_str(needle);
        } else {
            out.push_str(with);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn pct(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---- seeding and observation ----------------------------------------------

#[derive(Default)]
struct Labels {
    meetings: Vec<(i64, String)>,
    breakouts: Vec<(i64, String)>,
    recordings: Vec<(i64, String)>,
    rooms: Vec<(String, String)>,
    users: Vec<(i64, String)>,
}

impl Labels {
    fn meeting(&mut self, id: i64, room: &str) -> String {
        let label = format!("<meeting-{}>", self.meetings.len() + 1);
        self.meetings.push((id, label.clone()));
        self.rooms
            .push((room.to_owned(), format!("<room-{}>", self.meetings.len())));
        label
    }
}

async fn meeting(
    c: &tokio_postgres::Client,
    labels: &mut Labels,
    owner: i64,
    state: &str,
    created_ago: i64,
    ended_ago: Option<i64>,
    settings: &str,
) -> Result<(i64, String), BoxError> {
    let row = c
        .query_one(
            "INSERT INTO meetings(title, owner_user_id, state, created_at, ended_at, settings) \
             VALUES('meet5 worker', $1, $2, now() - make_interval(secs => $3::int), \
                    CASE WHEN $4::int IS NULL THEN NULL ELSE now() - make_interval(secs => $4::int) END, $5::text::jsonb) \
             RETURNING id, room_name::text",
            &[&owner, &state, &(created_ago as i32), &ended_ago.map(|v| v as i32), &settings],
        )
        .await?;
    let (id, room): (i64, String) = (row.get(0), row.get(1));
    labels.meeting(id, &room);
    Ok((id, room))
}

async fn participant(
    c: &tokio_postgres::Client,
    meeting: i64,
    user: Option<i64>,
    identity: &str,
    role: &str,
    breakout: Option<i64>,
    left: bool,
) -> Result<(), BoxError> {
    c.execute(
        "INSERT INTO meeting_participants(meeting_id,user_id,identity,role,joined_at,left_at,breakout_id) \
         VALUES($1,$2,$3,$4, now() - interval '30 minutes', CASE WHEN $5 THEN now() - interval '20 minutes' END, $6)",
        &[&meeting, &user, &identity, &role, &left, &breakout],
    )
    .await?;
    Ok(())
}

async fn recording(
    c: &tokio_postgres::Client,
    labels: &mut Labels,
    meeting: i64,
    started_by: i64,
    state: &str,
    egress: Option<&str>,
    staging: Option<&str>,
    age: i64,
    attempts: i32,
) -> Result<i64, BoxError> {
    let id: i64 = c
        .query_one(
            "INSERT INTO meeting_recordings(meeting_id,state,started_by,started_at,egress_id,staging_key,ingest_attempts) \
             VALUES($1,$2,$3, now() - make_interval(secs => $4::int), $5, $6, $7) RETURNING id",
            &[&meeting, &state, &started_by, &(age as i32), &egress, &staging, &attempts],
        )
        .await?
        .get(0);
    labels
        .recordings
        .push((id, format!("<recording-{}>", labels.recordings.len() + 1)));
    Ok(id)
}

struct Fixture {
    peers: Peers,
    labels: Labels,
    meetings: Vec<i64>,
}

async fn seed(
    case: &str,
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
    peers: &Peers,
) -> Result<Fixture, BoxError> {
    let mut labels = Labels::default();
    labels.users = vec![(a.user, "<owner>".into()), (b.user, "<member>".into())];
    let mut meetings = Vec::new();
    let mut st = |f: &mut dyn FnMut(&mut SfuState)| f(&mut peers.lock().unwrap());
    let long = 3600;
    match case {
        "lobby-expiry" => {
            let (m, room) = meeting(c, &mut labels, a.user, "live", 120, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            c.execute("INSERT INTO meeting_join_requests(meeting_id,display_name,state,expires_at) VALUES($1,'guest','pending', now() - interval '1 minute')", &[&m]).await?;
            c.execute("INSERT INTO meeting_join_requests(meeting_id,display_name,state,expires_at) VALUES($1,'later','pending', now() + interval '10 minutes')", &[&m]).await?;
            st(&mut |s| s.rooms = vec![room.clone()]);
            meetings.push(m);
        }
        "ended-room-delete" => {
            let (m, room) = meeting(c, &mut labels, a.user, "ended", long, Some(60), "{}").await?;
            st(&mut |s| s.rooms = vec![room.clone()]);
            meetings.push(m);
        }
        "breakout-room-gc" => {
            let (m, _room) = meeting(c, &mut labels, a.user, "live", long, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            let (bid, broom): (i64, String) = {
                let r = c.query_one("INSERT INTO meeting_breakouts(meeting_id,idx,state,closed_at) VALUES($1,1,'closed', now() - interval '5 minutes') RETURNING id, room_name::text", &[&m]).await?;
                (r.get(0), r.get(1))
            };
            labels.breakouts.push((bid, "<breakout-1>".into()));
            labels
                .rooms
                .push((broom.clone(), "<breakout-room-1>".into()));
            st(&mut |s| s.rooms = vec![broom.clone()]);
            meetings.push(m);
        }
        "lost-webhook-gc" | "lost-webhook-quiet" => {
            let (m, room) = meeting(c, &mut labels, a.user, "live", long, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                true,
            )
            .await?;
            c.execute("UPDATE meeting_participants SET left_at = now() - interval '30 minutes' WHERE meeting_id=$1", &[&m]).await?;
            if case == "lost-webhook-quiet" {
                st(&mut |s| s.rooms = vec![room.clone()]);
            }
            meetings.push(m);
        }
        "breakout-presence-heal" | "breakout-absent-first-tick" => {
            let (m, room) = meeting(c, &mut labels, a.user, "live", long, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            let r = c.query_one("INSERT INTO meeting_breakouts(meeting_id,idx,state) VALUES($1,1,'open') RETURNING id, room_name::text", &[&m]).await?;
            let (bid, broom): (i64, String) = (r.get(0), r.get(1));
            labels.breakouts.push((bid, "<breakout-1>".into()));
            labels
                .rooms
                .push((broom.clone(), "<breakout-room-1>".into()));
            let ident = format!("u:{}", b.user);
            participant(c, m, Some(b.user), &ident, "member", Some(bid), false).await?;
            st(&mut |s| {
                s.rooms = vec![room.clone(), broom.clone()];
                if case == "breakout-presence-heal" {
                    // assigned to the breakout, present in the main room
                    s.participants.insert(room.clone(), vec![ident.clone()]);
                }
            });
            meetings.push(m);
        }
        "captions-crashed" | "captions-orphan" | "captions-grace" => {
            let since = if case == "captions-grace" {
                "now() + interval '5 minutes'"
            } else {
                "now() - interval '10 minutes'"
            };
            let settings = format!(
                "{{\"captionsOn\": {}, \"captionsSince\": \"{}\"}}",
                case != "captions-orphan",
                "SINCE"
            );
            let (state, ended) = if case == "captions-orphan" {
                ("ended", Some(600))
            } else {
                ("live", None)
            };
            let (m, room) = meeting(c, &mut labels, a.user, state, long, ended, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            let on = case != "captions-orphan";
            c.execute(
                &format!("UPDATE meetings SET settings = jsonb_build_object('captionsOn', $2::boolean, 'captionsSince', ({since})::text) WHERE id=$1"),
                &[&m, &on],
            )
            .await?;
            let _ = settings;
            st(&mut |s| {
                s.rooms = vec![room.clone()];
                if case == "captions-orphan" {
                    s.asr_rooms = vec![room.clone()];
                }
            });
            meetings.push(m);
        }
        "recording-ended-residue" | "recording-stop-retry" => {
            let (state, ended) = if case == "recording-ended-residue" {
                ("ended", Some(30))
            } else {
                ("live", None)
            };
            let (m, room) = meeting(c, &mut labels, a.user, state, long, ended, "{}").await?;
            let rec_state = if case == "recording-stop-retry" {
                "stopping"
            } else {
                "active"
            };
            recording(
                c,
                &mut labels,
                m,
                a.user,
                rec_state,
                Some("EG_one"),
                Some("meet-egress/1-x.mp4"),
                600,
                0,
            )
            .await?;
            st(&mut |s| {
                s.rooms = vec![room.clone()];
                s.egress = vec![("EG_one".into(), 1, (now() - 600) * 1_000_000_000)];
            });
            meetings.push(m);
        }
        "recording-stale-requested" => {
            let (m, room) = meeting(c, &mut labels, a.user, "live", long, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            recording(c, &mut labels, m, a.user, "requested", None, None, 600, 0).await?;
            st(&mut |s| s.rooms = vec![room.clone()]);
            meetings.push(m);
        }
        "recording-vanished-failed" | "recording-vanished-complete" => {
            let (m, room) = meeting(c, &mut labels, a.user, "live", long, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            let key = "meet-egress/9-vanish.mp4";
            recording(
                c,
                &mut labels,
                m,
                a.user,
                "active",
                Some("EG_gone"),
                Some(key),
                600,
                0,
            )
            .await?;
            st(&mut |s| {
                s.rooms = vec![room.clone()];
                if case == "recording-vanished-complete" {
                    s.objects.insert(key.into(), (vec![7u8; 1234], now() - 100));
                }
            });
            meetings.push(m);
        }
        "egress-belt" | "egress-young" => {
            let (m, room) = meeting(c, &mut labels, a.user, "live", long, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            let started = if case == "egress-young" {
                now() - 10
            } else {
                now() - 900
            };
            st(&mut |s| {
                s.rooms = vec![room.clone()];
                s.egress = vec![
                    ("EG_stray".into(), 1, started * 1_000_000_000),
                    ("EG_done".into(), 3, 0),
                ];
            });
            meetings.push(m);
        }
        "local-lease-expire" => {
            let (m, room) = meeting(c, &mut labels, a.user, "live", long, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            st(&mut |s| s.rooms = vec![room.clone()]);
            meetings.push(m);
            // The lease/recording rows come from the reducers' own tables.
            seed_local_lease(c, &mut labels, m, a.user).await?;
        }
        "semantic-sweep" | "semantic-export" | "drive-history" => {
            let (m, room) = meeting(c, &mut labels, a.user, "live", long, None, "{}").await?;
            participant(
                c,
                m,
                Some(a.user),
                &format!("u:{}", a.user),
                "host",
                None,
                false,
            )
            .await?;
            let (rec_state, package) = match case {
                "semantic-sweep" => ("stopped", "DELETE_PENDING"),
                "drive-history" => ("stopped", "ACTIVE"),
                _ => ("stopped", "ACTIVE"),
            };
            let rec: i64 = c
                .query_one(
                    "INSERT INTO meeting_semantic_recordings(meeting_id, started_by, rec_state, package_state, deletion_generation, stopped_at) VALUES($1,$2,$3,$4,1,now()) RETURNING id",
                    &[&m, &a.user, &rec_state, &package],
                )
                .await?
                .get(0);
            labels.recordings.push((rec, "<semantic-recording>".into()));
            if case == "semantic-sweep" {
                for child in ["manifest.json", "timeline.ndjson"] {
                    c.execute(
                        "INSERT INTO meeting_semantic_children(recording_id, child) VALUES($1,$2)",
                        &[&rec, &child],
                    )
                    .await?;
                }
            }
            if case == "semantic-export" {
                c.execute(
                    "INSERT INTO meeting_semantic_exports(recording_id, generation) VALUES($1,1)",
                    &[&rec],
                )
                .await?;
            }
            st(&mut |s| s.rooms = vec![room.clone()]);
            meetings.push(m);
        }
        "feature-off" => {
            let (m, room) = meeting(c, &mut labels, a.user, "ended", long, Some(60), "{}").await?;
            recording(
                c,
                &mut labels,
                m,
                a.user,
                "active",
                Some("EG_one"),
                None,
                600,
                0,
            )
            .await?;
            st(&mut |s| s.rooms = vec![room.clone()]);
            meetings.push(m);
        }
        "list-rooms-fails" => {
            let (m, room) = meeting(c, &mut labels, a.user, "ended", long, Some(60), "{}").await?;
            c.execute("INSERT INTO meeting_join_requests(meeting_id,display_name,state,expires_at) VALUES($1,'guest','pending', now() - interval '1 minute')", &[&m]).await?;
            st(&mut |s| {
                s.rooms = vec![room.clone()];
                s.fail_list_rooms = true;
            });
            meetings.push(m);
        }
        "ingest-recording" | "ingest-exhausted" | "ingest-success" => {
            let m = if case == "ingest-success" {
                // The real reducer provisions the chat channel and Drive space the ingest needs.
                let created: Value = serde_json::from_str(
                    &c.query_one(
                        "SELECT meeting_create($1,'meet5 ingest',NULL,NULL,NULL,NULL,true)::text",
                        &[&a.user],
                    )
                    .await?
                    .get::<_, String>(0),
                )?;
                let m = created["meetingId"].as_i64().unwrap();
                let room = created["roomName"].as_str().unwrap().to_owned();
                labels.meeting(m, &room);
                c.execute("UPDATE meetings SET state='ended', ended_at = now() - interval '1 minute' WHERE id=$1", &[&m]).await?;
                m
            } else {
                meeting(c, &mut labels, a.user, "ended", long, Some(60), "{}")
                    .await?
                    .0
            };
            let key = "meet-egress/5-ingest.mp4";
            let attempts = if case == "ingest-exhausted" { 5 } else { 0 };
            let size: usize = if case == "ingest-success" {
                9_000_000
            } else {
                5000
            };
            recording(
                c,
                &mut labels,
                m,
                a.user,
                "pending_ingest",
                Some("EG_in"),
                Some(key),
                900,
                attempts,
            )
            .await?;
            st(&mut |s| {
                s.objects.insert(
                    key.into(),
                    (
                        (0..size as u32).map(|i| (i % 251) as u8).collect(),
                        now() - 100,
                    ),
                );
            });
            meetings.push(m);
        }
        "reap-staging" => {
            let (m, _room) = meeting(c, &mut labels, a.user, "ended", long, Some(60), "{}").await?;
            recording(
                c,
                &mut labels,
                m,
                a.user,
                "ready",
                Some("EG_r"),
                Some("meet-egress/1-ready.mp4"),
                900,
                0,
            )
            .await?;
            recording(
                c,
                &mut labels,
                m,
                a.user,
                "failed",
                Some("EG_f1"),
                Some("meet-egress/2-old-failed.mp4"),
                900,
                0,
            )
            .await?;
            recording(
                c,
                &mut labels,
                m,
                a.user,
                "failed",
                Some("EG_f2"),
                Some("meet-egress/3-new-failed.mp4"),
                900,
                0,
            )
            .await?;
            recording(
                c,
                &mut labels,
                m,
                a.user,
                "active",
                Some("EG_a"),
                Some("meet-egress/4-active.mp4"),
                900,
                0,
            )
            .await?;
            st(&mut |s| {
                let week = 8 * 24 * 3600;
                for (k, age) in [
                    ("meet-egress/1-ready.mp4", 100),
                    ("meet-egress/2-old-failed.mp4", week),
                    ("meet-egress/3-new-failed.mp4", 100),
                    ("meet-egress/4-active.mp4", week),
                    ("meet-egress/6-orphan-old.mp4", week),
                    ("meet-egress/7-orphan-new.mp4", 100),
                    ("other/untouched.bin", week),
                ] {
                    s.objects.insert(k.into(), (vec![1, 2, 3], now() - age));
                }
            });
            meetings.push(m);
        }
        other => return Err(format!("unknown case {other}").into()),
    }
    Ok(Fixture {
        peers: peers.clone(),
        labels,
        meetings,
    })
}

async fn seed_local_lease(
    c: &tokio_postgres::Client,
    labels: &mut Labels,
    meeting: i64,
    owner: i64,
) -> Result<(), BoxError> {
    let rec: i64 = c
        .query_one(
            "INSERT INTO meeting_semantic_recordings(meeting_id, started_by, rec_state) VALUES($1,$2,'active') RETURNING id",
            &[&meeting, &owner],
        )
        .await
        .map_err(|e| format!("semantic recording seed: {e}"))?
        .get(0);
    labels.recordings.push((rec, "<semantic-recording>".into()));
    c.execute(
        "INSERT INTO meeting_local_capture_leases(meeting_id,recording_id,device_id,lease_state,generation,surfaces,producer,heartbeat_seconds,expires_at,started_by) \
         VALUES($1,$2,'dev','live',1,'[\"audio\"]'::jsonb,'{}'::jsonb,10, now() - interval '1 minute',$3)",
        &[&meeting, &rec, &owner],
    )
    .await
    .map_err(|e| format!("lease seed: {e}"))?;
    Ok(())
}

fn mask(value: &mut Value, labels: &Labels) {
    match value {
        Value::String(s) => {
            if s.len() >= 19 && s.as_bytes()[4] == b'-' && matches!(s.as_bytes()[10], b'T' | b' ') {
                *s = "<timestamp>".into();
            }
            if let Some(rest) = s.strip_prefix("Recording \u{2014} ") {
                // "<title> — YYYY-MM-DD HH:MM (#id).mp4": the minute and id are volatile, the shape is not.
                if let Some((title, tail)) = rest.rsplit_once(" \u{2014} ") {
                    let b = tail.as_bytes();
                    let shaped = tail.len() > 17
                        && b[4] == b'-'
                        && b[7] == b'-'
                        && b[10] == b' '
                        && b[13] == b':'
                        && tail[16..].starts_with(" (#")
                        && tail.ends_with(").mp4");
                    if shaped {
                        *s = format!(
                            "Recording \u{2014} {title} \u{2014} <local-minute> (#<recording>).mp4"
                        );
                    }
                }
            }
            for (id, label) in &labels.users {
                for prefix in ["u:", "meet:"] {
                    *s = replace_token(s, &format!("{prefix}{id}"), &format!("{prefix}{label}"));
                }
            }
            for (id, label) in &labels.meetings {
                *s = replace_token(s, &format!("cc:{id}"), &format!("cc:{label}"));
            }
            for (room, label) in &labels.rooms {
                *s = s.replace(room.as_str(), label);
            }
            if s.starts_with("ingest failed") || s.contains("rror") && s.len() > 40 {
                // driver and client error text is not part of the contract
                *s = "<error-text>".into();
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| mask(v, labels)),
        Value::Object(o) => {
            for (k, v) in o.iter_mut() {
                let map: Option<&Vec<(i64, String)>> = match k.as_str() {
                    "breakout_id" | "breakoutId" => Some(&labels.breakouts),
                    "meetingId" => Some(&labels.meetings),
                    "recordingId" | "recording_id" => Some(&labels.recordings),
                    _ => None,
                };
                if let (Some(map), Some(n)) = (map, v.as_i64()) {
                    if let Some((_, label)) = map.iter().find(|(id, _)| *id == n) {
                        *v = json!(label);
                        continue;
                    }
                }
                mask(v, labels);
            }
        }
        _ => {}
    }
}

async fn observe_db(c: &tokio_postgres::Client, f: &Fixture) -> Result<Value, BoxError> {
    let ids = f.meetings.clone();
    let strip: Vec<String> = [
        "id",
        "meeting_id",
        "owner_user_id",
        "started_by",
        "user_id",
        "chat_channel_id",
        "slug",
        "room_name",
        "decided_by",
        "secret",
        "file_node_id",
        "version_id",
        "created_at",
        "source_id",
        "audit_id",
        "recording_id",
        "updated_at",
        "space_id",
        "drive_node_id",
        "drive_version_id",
        "actor_user_id",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let mut out = serde_json::Map::new();
    for (name, sql) in [
        ("meetings", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[] || jsonb_build_object('room', room_name::text)) ORDER BY id),'[]')::text FROM meetings t WHERE id = ANY($1)"),
        ("participants", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[]) ORDER BY meeting_id, identity),'[]')::text FROM meeting_participants t WHERE meeting_id = ANY($1)"),
        ("breakouts", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[] || jsonb_build_object('room', room_name::text)) ORDER BY id),'[]')::text FROM meeting_breakouts t WHERE meeting_id = ANY($1)"),
        ("recordings", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[]) ORDER BY id),'[]')::text FROM meeting_recordings t WHERE meeting_id = ANY($1)"),
        ("requests", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[]) ORDER BY id),'[]')::text FROM meeting_join_requests t WHERE meeting_id = ANY($1)"),
        ("leases", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[]) ORDER BY id),'[]')::text FROM meeting_local_capture_leases t WHERE meeting_id = ANY($1)"),
        ("semantic", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[]) ORDER BY id),'[]')::text FROM meeting_semantic_recordings t WHERE meeting_id = ANY($1)"),
        ("semantic_children", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[]) ORDER BY id),'[]')::text FROM meeting_semantic_children t WHERE recording_id IN (SELECT id FROM meeting_semantic_recordings WHERE meeting_id = ANY($1))"),
        ("semantic_exports", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[]) ORDER BY id),'[]')::text FROM meeting_semantic_exports t WHERE recording_id IN (SELECT id FROM meeting_semantic_recordings WHERE meeting_id = ANY($1))"),
        ("ingested_nodes", "SELECT coalesce(jsonb_agg(jsonb_build_object('name', n.name, 'kind', n.kind, 'versions', (SELECT jsonb_agg(jsonb_build_object('size', v.size_bytes, 'sha256', v.content_sha256, 'type', v.content_type, 'note', v.note, 'device', v.device_label, 'chunks', (SELECT count(*) FROM drive_version_chunks c WHERE c.version_id = v.id)) ORDER BY v.id) FROM drive_file_versions v WHERE v.file_node_id = n.id)) ORDER BY n.id),'[]')::text FROM drive_nodes n WHERE n.id IN (SELECT file_node_id FROM meeting_recordings WHERE meeting_id = ANY($1)) AND $2::text[] IS NOT NULL"),
        ("drive_history", "SELECT coalesce(jsonb_agg((to_jsonb(t) - $2::text[]) ORDER BY id),'[]')::text FROM drive_meet_history_events t WHERE source_kind='recording.stopped' AND source_id IN (SELECT id FROM meeting_semantic_recordings WHERE meeting_id = ANY($1))"),
    ] {
        let raw: String = c.query_one(sql, &[&ids, &strip]).await?.get(0);
        let rows: Value = serde_json::from_str(&raw)?;
        // Later tables appear only when a case produced rows, so earlier goldens stay valid.
        if matches!(name, "semantic_children" | "semantic_exports" | "drive_history" | "ingested_nodes") && rows == json!([]) {
            continue;
        }
        out.insert(name.into(), rows);
    }
    let mut v = Value::Object(out);
    mask(&mut v, &f.labels);
    Ok(v)
}

fn calls_of(peers: &Peers, labels: &Labels) -> Value {
    let mut st = peers.lock().unwrap();
    let mut v = json!({
        "livekit": std::mem::take(&mut st.calls),
        "asr": std::mem::take(&mut st.asr_calls),
        "objects": std::mem::take(&mut st.s3_ops),
        "stored": st.objects.iter().map(|(k, (d, _))| json!({"key":k,"size":d.len()})).collect::<Vec<_>>(),
    });
    // Random temporary keys are not part of the contract.
    let text = v.to_string().replace(|c| c == '\u{0}', "");
    let _ = text;
    fix_temp(&mut v);
    mask(&mut v, labels);
    v
}

fn fix_temp(v: &mut Value) {
    match v {
        Value::String(s) if s.starts_with("tmp/upload/") => *s = "tmp/upload/<random>".into(),
        Value::Array(a) => a.iter_mut().for_each(fix_temp),
        Value::Object(o) => o.values_mut().for_each(fix_temp),
        _ => {}
    }
}

// ---- the case runner -------------------------------------------------------

async fn run(case: &'static str, mutant: Mutant) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let recording_run = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    if mutant != Mutant::None && recording_run {
        return Err("cannot record a planted mutant".into());
    }
    let Some(db) = Db::for_case("meet5-worker") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "meet5w-owner").await?;
    let b = fixture::account(&c, "meet5w-member").await?;
    let saved: Option<bool> = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.meet'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let peers: Peers = Arc::default();
    let result = std::panic::AssertUnwindSafe(async {
        c.execute(
            "INSERT INTO feature_toggles(key,enabled) VALUES('feature.meet',$1) ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled",
            &[&(case != "feature-off")],
        )
        .await?;
        let sfu = twirp(peers.clone()).await;
        let asr_addr = asr(peers.clone()).await;
        let s3_addr = s3(peers.clone()).await;
        let fx = seed(case, &c, &a, &b, &peers).await?;
        let mut listeners = Vec::new();
        for channel in [format!("meet:{}", a.user), format!("meet:{}", b.user)] {
            listeners.push((channel.clone(), db.listen(&channel).await?));
        }
        if recording_run {
            std::env::set_var("GOFREE_ORACLE_KEEP_WORKERS", "meet-reconcile");
            let env: Vec<(&str, String)> = vec![
                ("LIVEKIT_API_KEY", KEY.into()),
                ("LIVEKIT_API_SECRET", SECRET.into()),
                ("LIVEKIT_URL", format!("ws://{sfu}")),
                ("MEET_EGRESS_ENABLED", "true".into()),
                ("ASR_URL", format!("http://{asr_addr}")),
                ("ASR_TOKEN", ASR_TOKEN.into()),
            ];
            let oracle = common::go_oracle::start_named_with_env(
                &Db { dsn: db.dsn.clone(), direct: db.direct.clone(), app: db.app.clone() },
                s3_addr,
                "gofree-meet5w",
                &env,
            )
            .await?
            .ok_or("no Go oracle")?;
            // Startup probes are not tick traffic; the worker's first tick is
            // 60 s after launch.
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            let _ = calls_of(&peers, &fx.labels);
            tokio::time::sleep(std::time::Duration::from_secs(66)).await;
            drop(oracle);
        } else {
            let livekit = if mutant == Mutant::Unconfigured {
                LiveKit::unconfigured()
            } else {
                LiveKit::new(KEY, SECRET, &format!("ws://{sfu}"), true, true).with_asr(&format!("http://{asr_addr}"), ASR_TOKEN)
            };
            let worker = MeetReconcile::new(
                setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?.with_audit_keys("22".repeat(32), String::new()),
                livekit,
                Some(S3Store::new(&format!("http://{s3_addr}"), BUCKET, "test-access", "test-secret")?),
            );
            worker.tick().await;
        }
        let notify = meet_fixture::events(&mut listeners, &c).await?;
        let mut notify = notify;
        mask(&mut notify, &fx.labels);
        let observation = json!({
            "db": observe_db(&c, &fx).await?,
            "notify": notify,
            "peripherals": calls_of(&fx.peers, &fx.labels),
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../tests/conformance/meet/goldens/worker-{case}.json"));
        if recording_run {
            setjoin_conformance::golden::record(
                &path,
                &json!({"format":1,"worker":"meet-reconcile","case":format!("worker-{case}"),
                    "go_source":std::env::var("GOFREE_GO_SOURCE")?,
                    "normalization":["generated ids, room names and timestamps masked; object temp keys masked"],
                    "observation":observation}),
            )?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            setjoin_conformance::golden::compare(&expected["observation"], &observation)?;
            println!("GOLDEN-REPLAY: meet-reconcile :: worker-{case}");
        }
        Ok::<_, BoxError>(())
    })
    .await;
    match saved {
        Some(v) => {
            c.execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.meet'",
                &[&v],
            )
            .await?;
        }
        None => {
            c.execute("DELETE FROM feature_toggles WHERE key='feature.meet'", &[])
                .await?;
        }
    }
    purge(&c, &[a.user, b.user]).await?;
    let cleaned = meet_fixture::cleanup(&c, &[&a, &b]).await;
    // A fixture left behind would sit in every later suite's directory; surface it.
    result.and(cleaned)
}

/// Removes every meeting row (and what hangs off it) the case's accounts own, so
/// the next case's tick sees nothing but its own seed. Replica mode skips the FK
/// triggers; only these fixture tables are touched.
async fn purge(c: &tokio_postgres::Client, users: &[i64]) -> Result<(), BoxError> {
    let owners = users.to_vec();
    let mut sql = String::from("BEGIN; SET LOCAL session_replication_role = replica;");
    let scope = "SELECT id FROM meetings WHERE owner_user_id = ANY(ARRAY[".to_owned()
        + &owners
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",")
        + "]::bigint[])";
    for stmt in [
        format!("DELETE FROM meeting_semantic_children WHERE recording_id IN (SELECT id FROM meeting_semantic_recordings WHERE meeting_id IN ({scope}))"),
        format!("DELETE FROM meeting_semantic_exports WHERE recording_id IN (SELECT id FROM meeting_semantic_recordings WHERE meeting_id IN ({scope}))"),
        format!("DELETE FROM drive_meet_history_events WHERE meeting_id IN ({scope})"),
        format!("DELETE FROM meeting_local_capture_leases WHERE meeting_id IN ({scope})"),
        format!("DELETE FROM meeting_semantic_recordings WHERE meeting_id IN ({scope})"),
        format!("DELETE FROM meeting_recordings WHERE meeting_id IN ({scope})"),
        format!("DELETE FROM meeting_join_requests WHERE meeting_id IN ({scope})"),
        format!("DELETE FROM meeting_breakouts WHERE meeting_id IN ({scope})"),
        format!("DELETE FROM meeting_participants WHERE meeting_id IN ({scope})"),
        format!("DELETE FROM meetings WHERE id IN ({scope})"),
    ] {
        sql.push_str(&stmt);
        sql.push(';');
    }
    sql.push_str("COMMIT;");
    c.batch_execute(&sql).await?;
    Ok(())
}
