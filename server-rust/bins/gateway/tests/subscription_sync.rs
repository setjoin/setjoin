//! Calendar subscription sync worker (#298): seed plus one tick against frozen Go's
//! real `calendarsync.Worker` (overlay `tests/conformance/calendar/sync_test.go.txt`),
//! compared on the committed rows and on the requests the feed fixture saw. Record
//! with `GOFREE_RECORD_SYNC=1` and `GOFREE_GO_SOURCE=<sha>` (needs the CI image);
//! replay runs the Rust worker.
//!
//! Three cases: `tick` (the due-poll over many feeds, loopback fixture through the
//! unguarded client as Go's own tests do), `guarded` (the production client must
//! refuse every loopback spelling) and `kick` (the subscribe route's detached first
//! fetch). The fixture serves `localhost` URLs so redirects pass the literal-address
//! check; `127.0.0.1` redirect targets are refused, as in Go.
mod common;
use common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::subscription_sync::SubscriptionSync;
use setjoin_pg::workers::WorkerDatabase;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn port() -> u16 {
    std::env::var("GOFREE_FEED_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(19298)
}

const CAL: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//gofree//EN\r\n";

fn wrap(body: &str) -> Vec<u8> {
    format!("{CAL}{body}END:VCALENDAR\r\n").into_bytes()
}

fn ok_feed() -> Vec<u8> {
    let mut feed = wrap(concat!(
        "BEGIN:VTIMEZONE\r\nTZID:America/New_York\r\nBEGIN:STANDARD\r\nDTSTART:19701101T020000\r\nTZOFFSETFROM:-0400\r\nTZOFFSETTO:-0500\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n",
        "BEGIN:VEVENT\r\nUID:ok-utc\r\nDTSTART:20400101T090000Z\r\nDTEND:20400101T093000Z\r\nSUMMARY:Stand\\, up <b>&amp; \"q\"\r\nDESCRIPTION:line one\\nline two\\; with\r\n  a folded part\\\\\r\nLOCATION:Room 1\r\nSTATUS:TENTATIVE\r\nRRULE:FREQ=WEEKLY;BYDAY=MO\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-tz\r\nDTSTART;TZID=America/New_York:20400301T090000\r\nDTEND;TZID=America/New_York:20400301T100000\r\nSUMMARY:NY\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-gap\r\nDTSTART;TZID=America/New_York:20240310T023000\r\nDTEND;TZID=America/New_York:20240310T033000\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-overlap\r\nDTSTART;TZID=America/New_York:20241103T013000\r\nDTEND;TZID=America/New_York:20241103T023000\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-london\r\nDTSTART;TZID=Europe/London:20240701T120000\r\nDTEND;TZID=Europe/London:20240701T130000\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-kolkata\r\nDTSTART;TZID=Asia/Kolkata:20240701T120000\r\nDTEND;TZID=Asia/Kolkata:20240701T130000\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-unknown-tz\r\nDTSTART;TZID=Mars/Phobos:20240701T120000\r\nDTEND;TZID=../etc/passwd:20240701T130000\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-allday\r\nDTSTART;VALUE=DATE:20400704\r\nDTEND;VALUE=DATE:20400705\r\nSUMMARY:Holiday\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-offset\r\nDTSTART:20400101T090000-0500\r\nDTEND:20400101T100000+0530\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-frac\r\nDTSTART:20400101T090000.250Z\r\nDTEND;TZID=Europe/Paris:20400101T100000.5\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-bare\r\nDTSTART:20400101T090000\r\nDTEND:20400102\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-bad-dates\r\nDTSTART:20401301T090000Z\r\nDTEND:20400230T090000Z\r\nSUMMARY:Bad dates\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-lower\r\nsummary:Lower summary\r\ndtstart:20400101T090000Z\r\nlocation:Lower place\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-alarm\r\nSUMMARY:With alarm\r\nBEGIN:VALARM\r\nSUMMARY:Alarm text\r\nACTION:DISPLAY\r\nEND:VALARM\r\nSTATUS: confirmed\r\nEND:VEVENT\r\n",
        "BEGIN:VTODO\r\nUID:ok-todo\r\nDUE;VALUE=DATE:20400101\r\nSTATUS:NEEDS-ACTION\r\nSUMMARY:Todo\r\nEND:VTODO\r\n",
        "BEGIN:VJOURNAL\r\nUID:ok-journal\r\nSUMMARY:Journal\r\nEND:VJOURNAL\r\n",
        "BEGIN:VEVENT\r\nUID:ok-bogus-status\r\nSTATUS:BOGUS\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-dup\r\nSUMMARY:first\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-dup\r\nSUMMARY:second\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-cancelled\r\nSTATUS:cancelled\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:ok-untitled\r\nEND:VEVENT\r\n",
    ));
    // A raw Latin-1 byte and a line feed without a carriage return.
    let tail = b"BEGIN:VEVENT\nUID:ok-latin1\nSUMMARY:caf\xe9 \xe2\x82\nLOCATION:\xf0\x9f\x98\x80 ok\nEND:VEVENT\n";
    feed.truncate(feed.len() - "END:VCALENDAR\r\n".len());
    feed.extend_from_slice(tail);
    feed.extend_from_slice(b"END:VCALENDAR\r\n");
    feed
}

fn small(uid: &str, title: &str) -> Vec<u8> {
    wrap(&format!(
        "BEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:{title}\r\nDTSTART:20400101T090000Z\r\nDTEND:20400101T100000Z\r\nEND:VEVENT\r\n"
    ))
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, Vec<u8>)>,
    body: Vec<u8>,
}

fn reply(status: u16, body: Vec<u8>) -> Reply {
    Reply {
        status,
        headers: vec![("Content-Type", b"text/calendar".to_vec())],
        body,
    }
}

fn redirect(status: u16, location: Option<&str>) -> Reply {
    let mut r = reply(status, Vec::new());
    if let Some(l) = location {
        r.headers.push(("Location", l.as_bytes().to_vec()));
    }
    r
}

fn exact_size() -> Vec<u8> {
    let mut feed = small("exact", "At the limit");
    feed.truncate(feed.len() - "END:VCALENDAR\r\n".len());
    let fill = (5usize << 20) - feed.len() - "END:VCALENDAR\r\n".len();
    // Lines of 1000 bytes; the last one absorbs the remainder.
    let (lines, rest) = (fill / 1000, fill % 1000);
    for n in 0..lines {
        let size = if n + 1 == lines { 1000 + rest } else { 1000 };
        feed.extend_from_slice(b"X-P:");
        feed.extend(std::iter::repeat(b'p').take(size - 6));
        feed.extend_from_slice(b"\r\n");
    }
    feed.extend_from_slice(b"END:VCALENDAR\r\n");
    assert_eq!(feed.len(), 5 << 20);
    feed
}

fn route(path: &str) -> Reply {
    let validators = |mut r: Reply| {
        r.headers.push(("ETag", b"\"v-ok\"".to_vec()));
        r.headers
            .push(("Last-Modified", b"Wed, 01 Jan 2040 00:00:00 GMT".to_vec()));
        r
    };
    match path {
        "/ok" => validators(reply(200, ok_feed())),
        "/update" => validators(reply(
            200,
            wrap("BEGIN:VEVENT\r\nUID:u-keep\r\nSUMMARY:New title\r\nDTSTART:20400501T090000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:u-new\r\nSUMMARY:Brand new\r\nEND:VEVENT\r\n").into_iter().collect(),
        )),
        "/partial" => reply(
            200,
            wrap("BEGIN:VEVENT\r\nSUMMARY:no uid\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:p-good\r\nSUMMARY:Good\r\nEND:VEVENT\r\n"),
        ),
        "/allbad" => reply(
            200,
            wrap("BEGIN:VEVENT\r\nSUMMARY:a\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nSUMMARY:b\r\nEND:VEVENT\r\n"),
        ),
        "/empty" => reply(200, wrap("")),
        "/garbage" => reply(200, b"<html>not a calendar</html>".to_vec()),
        "/nm" => redirect(304, None),
        "/gone" => reply(404, b"gone".to_vec()),
        "/error500" => reply(500, b"boom".to_vec()),
        "/redir" => redirect(302, Some("/ok2")),
        "/redir301" => redirect(301, Some(&format!("http://localhost:{}/ok2", port()))),
        "/ok2" => reply(200, small("redir-ok", "Followed")),
        "/redir-loop" => redirect(302, Some("/redir-loop")),
        "/redir-chain5" => redirect(302, Some("/chain4")),
        "/chain4" => redirect(302, Some("/chain3")),
        "/chain3" => redirect(302, Some("/chain2")),
        "/chain2" => redirect(302, Some("/chain1")),
        "/chain1" => redirect(302, Some("/ok2")),
        "/redir-loopback" => redirect(302, Some(&format!("http://127.0.0.1:{}/ok2", port()))),
        "/redir-private" => redirect(302, Some("http://169.254.169.254/latest/meta-data")),
        "/redir-noloc" => redirect(302, None),
        "/redir-scheme" => redirect(302, Some("ftp://localhost/x")),
        "/redir-webcal" => redirect(302, Some("webcal://example.org/x.ics")),
        "/big" => reply(200, {
            let mut b = small("big", "Too big");
            b.extend(std::iter::repeat(b'z').take(5 << 20));
            b
        }),
        "/exact" => reply(200, exact_size()),
        "/nul" => reply(
            200,
            wrap("BEGIN:VEVENT\r\nUID:nul-1\r\nDESCRIPTION:a\0b\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:nul-2\r\nEND:VEVENT\r\n"),
        ),
        "/bad-etag" => {
            let mut r = reply(200, small("bad-etag", "Bad validator"));
            r.headers.push(("ETag", b"\"caf\xe9\"".to_vec()));
            r
        }
        "/no-validators" => reply(200, small("plain", "No validators")),
        "/blank-etag" => {
            let mut r = reply(200, small("blank", "Blank validators"));
            r.headers.push(("ETag", Vec::new()));
            r
        }
        _ => reply(404, Vec::new()),
    }
}

type Log = Arc<Mutex<Vec<String>>>;

async fn serve(listener: TcpListener, log: Log) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let log = log.clone();
        tokio::spawn(async move {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match socket.read(&mut byte).await {
                    Ok(1) => head.push(byte[0]),
                    _ => return,
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            let mut lines = text.split("\r\n");
            let request = lines.next().unwrap_or_default().to_owned();
            let path = request.split(' ').nth(1).unwrap_or("/").to_owned();
            let mut seen = Vec::new();
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    let k = k.trim().to_ascii_lowercase();
                    if matches!(
                        k.as_str(),
                        "if-none-match" | "if-modified-since" | "user-agent" | "accept"
                    ) {
                        seen.push(format!("{k}={}", v.trim()));
                    }
                }
            }
            seen.sort();
            log.lock()
                .unwrap()
                .push(format!("{} :: {}", request.split(' ').next().unwrap_or(""), path) + " :: " + &seen.join(" | "));
            let r = route(path.split('?').next().unwrap_or("/"));
            let mut out = format!(
                "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                r.status,
                r.body.len()
            )
            .into_bytes();
            for (k, v) in &r.headers {
                out.extend_from_slice(k.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(v);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\r\n");
            let _ = socket.write_all(&out).await;
            let _ = socket.write_all(&r.body).await;
            let _ = socket.shutdown().await;
        });
    }
}

struct Seed {
    sub: i64,
    cal: i64,
    url: String,
}

struct World {
    account: fixture::Account,
    subs: Vec<Seed>,
}

async fn seed_sub(
    owner: &tokio_postgres::Client,
    account: &fixture::Account,
    name: &str,
    url: &str,
    fetched: &str,
    interval: i32,
    validators: bool,
    events: &[(&str, &str)],
) -> Result<Seed, BoxError> {
    let cal: i64 = owner
        .query_one(
            &format!("INSERT INTO calendars(mailbox_id,name,color) VALUES({},'{name}','#6366f1') RETURNING id", account.mailbox),
            &[],
        )
        .await?
        .get(0);
    let (etag, modified) = if validators {
        ("'\"v-old\"'", "'Tue, 31 Dec 2039 00:00:00 GMT'")
    } else {
        ("NULL", "NULL")
    };
    let sub: i64 = owner
        .query_one(
            &format!(
                "INSERT INTO calendar_subscriptions(user_id,calendar_id,url,etag,last_modified,refresh_interval_minutes,last_fetch_at) \
                 VALUES({},{cal},'{url}',{etag},{modified},{interval},{fetched}) RETURNING id",
                account.user
            ),
            &[],
        )
        .await?
        .get(0);
    for (uid, title) in events {
        owner
            .batch_execute(&format!(
                "INSERT INTO calendar_events(calendar_id,uid,title,description,start_at,end_at,status) \
                 VALUES({cal},'{uid}','{title}','old description','2030-01-01T09:00:00Z','2030-01-01T10:00:00Z','tentative')"
            ))
            .await?;
    }
    Ok(Seed {
        sub,
        cal,
        url: url.to_owned(),
    })
}

async fn clean(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    // The due-poll sees every subscription: leave only this test's rows.
    owner
        .batch_execute("DELETE FROM calendars WHERE id IN (SELECT calendar_id FROM calendar_subscriptions)")
        .await?;
    Ok(())
}

const NULL: &str = "NULL";

async fn seed_tick(owner: &tokio_postgres::Client) -> Result<World, BoxError> {
    clean(owner).await?;
    let account = fixture::account(owner, "gofree-sync").await?;
    let p = port();
    let u = |path: &str| format!("http://localhost:{p}{path}");
    let mut subs = Vec::new();
    // (path, stale validators, pre-existing events). Each row gets its own age so the
    // due-poll order does not depend on heap order; the first is never fetched (NULL).
    let scenarios: &[(&str, bool, &[(&str, &str)])] = &[
        ("/ok", false, &[]),
        ("/partial", false, &[]),
        ("/allbad", false, &[("ab-1", "Untouched")]),
        ("/garbage", false, &[("g-1", "One"), ("g-2", "Two")]),
        ("/gone", false, &[("gone-1", "Untouched")]),
        ("/redir", false, &[]),
        ("/redir-loop", false, &[]),
        ("/redir-chain5", false, &[]),
        ("/redir-loopback", false, &[]),
        ("/redir-private", false, &[]),
        ("/redir-noloc", false, &[]),
        ("/redir-scheme", false, &[]),
        ("/big", false, &[]),
        ("/exact", false, &[]),
        ("/update", true, &[("u-keep", "Old title"), ("u-gone", "Going away")]),
        ("/nm", true, &[("nm-1", "Kept")]),
        ("/nul", false, &[("nul-old", "Survives")]),
        ("/bad-etag", false, &[("be-old", "Survives")]),
        ("/no-validators", true, &[]),
    ];
    for (n, (path, validators, events)) in scenarios.iter().enumerate() {
        let fetched = if n == 0 { NULL.to_owned() } else { format!("now() - interval '{} days'", 100 + n) };
        subs.push(seed_sub(owner, &account, &format!("c{path}"), &u(path), &fetched, 15, *validators, events).await?);
    }
    // Due by age only (twenty minutes against a fifteen-minute interval); two that are not due.
    subs.push(seed_sub(owner, &account, "c/due-age", &u("/no-validators?due"), "now() - interval '20 minutes'", 15, false, &[]).await?);
    subs.push(seed_sub(owner, &account, "c/not-due-recent", &u("/ok"), "now() - interval '1 minute'", 15, false, &[]).await?);
    subs.push(seed_sub(owner, &account, "c/not-due-long", &u("/ok"), "now() - interval '2 hours'", 1440, false, &[]).await?);
    Ok(World { account, subs })
}

async fn observe(owner: &tokio_postgres::Client, world: &World, log: &Log, seeded_at: &str) -> Result<Value, BoxError> {
    let mut subs = Vec::new();
    for s in &world.subs {
        let row = owner
            .query_one(
                &format!(
                    "SELECT last_status, last_error, etag, last_modified, \
                     last_fetch_at IS NOT NULL AND last_fetch_at >= '{seeded_at}'::timestamptz FROM calendar_subscriptions WHERE id={}",
                    s.sub
                ),
                &[],
            )
            .await?;
        let events = owner
            .query(
                &format!(
                    "SELECT jsonb_build_object('uid',uid,'title',title,'description',description,'location',location,'all_day',all_day,'timezone',timezone,'rrule',rrule,'status',status,\
                     'start',to_char(start_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'end',to_char(end_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))::text \
                     FROM calendar_events WHERE calendar_id={} ORDER BY uid",
                    s.cal
                ),
                &[],
            )
            .await?;
        let url = s.url.replace(&format!(":{}", port()), ":<port>");
        subs.push(json!({
            "url": url,
            "status": row.get::<_, String>(0),
            "error": row.get::<_, Option<String>>(1),
            "etag": row.get::<_, Option<String>>(2),
            "last_modified": row.get::<_, Option<String>>(3),
            "claimed": row.get::<_, bool>(4),
            "events": events.iter().map(|e| serde_json::from_str::<Value>(&e.get::<_, String>(0)).unwrap()).collect::<Vec<_>>(),
        }));
    }
    let mut requests = log.lock().unwrap().clone();
    requests.sort();
    Ok(json!({"subscriptions": subs, "requests": requests}))
}

async fn go_run(db: &Db, mode: &str, extra: &[(&str, String)]) -> Result<(), BoxError> {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize()?;
    let folder = root.join("test-results/gofree-cal3");
    std::fs::create_dir_all(&folder)?;
    std::fs::write(
        folder.join("overlay.json"),
        serde_json::to_vec(&json!({"Replace":{
            "/src/mailserver/internal/calendarsync/gofree_sync_test.go":"/src/server-rust/tests/conformance/calendar/sync_test.go.txt"
        }}))?,
    )?;
    let name = format!("gofree-cal3-sync-{}", std::process::id());
    if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(ledger)?,
            "Planned {name}, local Docker, go cache {}/go-cache; assigned DB only; --rm",
            folder.display()
        )?;
    }
    let mut command = std::process::Command::new("docker");
    command
        .args(["run", "--rm", "--name", &name, "--network", "host", "-v"])
        .arg(format!("{}:/src", root.display()))
        .args(["-v", &gofree_go_mod_mount(), "-w", "/src/mailserver", "-e"])
        .arg(format!("GOFREE_SYNC_DSN={}", db.dsn))
        .args(["-e", &format!("GOFREE_SYNC_MODE={mode}")]);
    for (k, v) in extra {
        command.args(["-e", &format!("{k}={v}")]);
    }
    let output = command
        .args(["-e", "GOMAXPROCS=1", "-e", "GOGC=50", "-e", "GOMEMLIMIT=768MiB"])
        .args(["-e", "GOCACHE=/src/test-results/gofree-cal3/go-cache"])
        .args([
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-vet=off",
            "-overlay=/src/test-results/gofree-cal3/overlay.json",
            "./internal/calendarsync",
            "-run",
            "^TestGoFreeSubscriptionSync$",
            "-count=1",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "frozen Go sync failed: {}",
            String::from_utf8_lossy(&output.stdout).lines().rev().take(8).collect::<Vec<_>>().join(" | ")
        )
        .into());
    }
    Ok(())
}

fn golden_path(case: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../tests/conformance/calendar/goldens/worker-subscription-sync-{case}.json"))
}

fn finish(case: &str, observation: Value, recording: bool) -> Result<(), BoxError> {
    let path = golden_path(case);
    if recording {
        let path_text = path.display().to_string();
        let _ = std::fs::remove_file(&path);
        setjoin_conformance::golden::record(
            &path,
            &json!({"format":1,"case":format!("subscription-sync-{case}"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
        println!("recorded {path_text}");
    } else {
        let golden: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        setjoin_conformance::golden::compare(&golden["observation"], &observation)?;
        println!("GOLDEN-REPLAY: worker calendar-subscription-sync :: {case}");
    }
    Ok(())
}

async fn start(owner: &tokio_postgres::Client) -> Result<String, BoxError> {
    Ok(owner.query_one("SELECT now()::text", &[]).await?.get(0))
}

async fn fixture_server() -> Result<(Log, tokio::task::JoinHandle<()>), BoxError> {
    let listener = TcpListener::bind(("127.0.0.1", port())).await?;
    let log: Log = Arc::default();
    let task = tokio::spawn(serve(listener, log.clone()));
    Ok((log, task))
}

#[tokio::test(flavor = "multi_thread")]
async fn subscription_sync_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("subscription-sync") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let world = seed_tick(&owner).await?;
    let (log, server) = fixture_server().await?;
    let seeded_at = start(&owner).await?;
    let recording = std::env::var_os("GOFREE_RECORD_SYNC").is_some();
    let result = async {
        if recording {
            go_run(&db, "tick", &[]).await?;
        } else {
            SubscriptionSync::unguarded_for_tests(WorkerDatabase::new(&db.dsn)?).tick().await;
        }
        let observation = observe(&owner, &world, &log, &seeded_at).await?;
        finish("tick", observation, recording)
    }
    .await;
    server.abort();
    clean(&owner).await?;
    common::remove_blob_account(&owner, &world.account).await?;
    result
}

#[tokio::test(flavor = "multi_thread")]
async fn subscription_sync_guarded_client_refuses_loopback() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("subscription-sync") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    clean(&owner).await?;
    let account = fixture::account(&owner, "gofree-sync").await?;
    let p = port();
    let mut subs = Vec::new();
    for (n, url) in [
        format!("http://127.0.0.1:{p}/ok"),
        format!("http://localhost:{p}/ok"),
        format!("http://[::1]:{p}/ok"),
        format!("http://2130706433:{p}/ok"),
        format!("http://0.0.0.0:{p}/ok"),
        format!("http://169.254.169.254:{p}/ok"),
        format!("http://[::ffff:127.0.0.1]:{p}/ok"),
        format!("webcal://127.0.0.1:{p}/ok"),
    ]
    .into_iter()
    .enumerate()
    {
        subs.push(seed_sub(&owner, &account, &format!("g{n}"), &url, NULL, 15, false, &[]).await?);
    }
    let world = World { account, subs };
    let (log, server) = fixture_server().await?;
    let seeded_at = start(&owner).await?;
    let recording = std::env::var_os("GOFREE_RECORD_SYNC").is_some();
    let result = async {
        if recording {
            go_run(&db, "guarded", &[]).await?;
        } else {
            SubscriptionSync::new(WorkerDatabase::new(&db.dsn)?).tick().await;
        }
        let observation = observe(&owner, &world, &log, &seeded_at).await?;
        if observation["requests"].as_array().is_some_and(|r| !r.is_empty()) {
            return Err("the guarded client reached the loopback fixture".into());
        }
        finish("guarded", observation, recording)
    }
    .await;
    server.abort();
    clean(&owner).await?;
    common::remove_blob_account(&owner, &world.account).await?;
    result
}

#[tokio::test(flavor = "multi_thread")]
async fn subscription_sync_kick_fetches_one_subscription_now() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("subscription-sync") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    clean(&owner).await?;
    let account = fixture::account(&owner, "gofree-sync").await?;
    let p = port();
    // The route stamps last_fetch_at on insert; the kicked row carries stale
    // validators that RefreshSubscriptionNow must ignore, and a second due row must
    // be left alone (it is not part of the kick).
    let kicked = seed_sub(&owner, &account, "kick", &format!("http://localhost:{p}/ok"), "now()", 15, true, &[("stale", "Stale")]).await?;
    let other = seed_sub(&owner, &account, "other", &format!("http://localhost:{p}/ok2"), NULL, 15, false, &[]).await?;
    let (kick_sub, kick_cal, kick_url) = (kicked.sub, kicked.cal, kicked.url.clone());
    let world = World { account, subs: vec![kicked, other] };
    let (log, server) = fixture_server().await?;
    let seeded_at = start(&owner).await?;
    let recording = std::env::var_os("GOFREE_RECORD_SYNC").is_some();
    let result = async {
        if recording {
            go_run(
                &db,
                "kick",
                &[
                    ("GOFREE_SYNC_SUB", kick_sub.to_string()),
                    ("GOFREE_SYNC_CAL", kick_cal.to_string()),
                    ("GOFREE_SYNC_URL", kick_url.clone()),
                ],
            )
            .await?;
        } else {
            SubscriptionSync::unguarded_for_tests(WorkerDatabase::new(&db.dsn)?)
                .refresh_now(kick_sub, kick_cal, kick_url.clone())
                .await;
        }
        let observation = observe(&owner, &world, &log, &seeded_at).await?;
        finish("kick", observation, recording)
    }
    .await;
    server.abort();
    clean(&owner).await?;
    common::remove_blob_account(&owner, &world.account).await?;
    result
}

#[tokio::test(flavor = "multi_thread")]
async fn subscription_sync_batch_cap() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("subscription-sync") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    clean(&owner).await?;
    let account = fixture::account(&owner, "gofree-sync").await?;
    let p = port();
    let mut subs = Vec::new();
    // Twenty-four due feeds, one age each: one tick claims the twenty oldest.
    for n in 1..=24 {
        subs.push(
            seed_sub(&owner, &account, &format!("cap{n}"), &format!("http://localhost:{p}/no-validators?cap{n}"), &format!("now() - interval '{n} days'"), 15, false, &[]).await?,
        );
    }
    let world = World { account, subs };
    let (log, server) = fixture_server().await?;
    let seeded_at = start(&owner).await?;
    let recording = std::env::var_os("GOFREE_RECORD_SYNC").is_some();
    let result = async {
        if recording {
            go_run(&db, "tick", &[]).await?;
        } else {
            SubscriptionSync::unguarded_for_tests(WorkerDatabase::new(&db.dsn)?).tick().await;
        }
        let observation = observe(&owner, &world, &log, &seeded_at).await?;
        finish("cap", observation, recording)
    }
    .await;
    server.abort();
    clean(&owner).await?;
    common::remove_blob_account(&owner, &world.account).await?;
    result
}

/// Host Go module cache for the Go recorder container (GOFREE_GO_MOD_CACHE, default $HOME/go/pkg/mod).
#[allow(dead_code)]
fn gofree_go_mod_mount() -> String {
    let host = std::env::var("GOFREE_GO_MOD_CACHE").unwrap_or_else(|_| {
        format!(
            "{}/go/pkg/mod",
            std::env::var("HOME").unwrap_or_else(|_| "/root".into())
        )
    });
    format!("{host}:/root/go/pkg/mod")
}
