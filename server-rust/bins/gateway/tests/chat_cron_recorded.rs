//! #365: Chat's two cron callbacks. Frozen Go's real cron Worker runs one tick
//! of each task over a seeded channel; the native callbacks must leave the
//! identical rows. Replay needs no Go process.
mod common;
use common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_pg::workers::WorkerDatabase;

const HMAC: &str = "gofree-chat-cron-oracle-hmac-key";
const GO_OFF: &str = "cron:chat-chain-anchor,cron:chat-purge-expired";
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// (phase, local wall-clock time of the Go tick, GO_WORKERS_OFF, native action)
#[derive(Clone, Copy)]
enum Native {
    Nothing,
    Anchor,
    Purge,
}
const PHASES: [(&str, &str, &str, Native); 4] = [
    // Go skips both tasks: no effect at all, so nothing may run in Rust either.
    ("go-off-skips", "02:40", GO_OFF, Native::Nothing),
    ("anchor", "02:40", "", Native::Anchor),
    ("purge", "02:50", "", Native::Purge),
    ("anchor-again", "02:40", "", Native::Anchor),
];

#[tokio::test]
async fn chat_cron_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("chat-cron-tick") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let recording = std::env::var_os("GOFREE_RECORD_CHAT_CRON").is_some();
    let prior: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat_compliance'",
            &[],
        )
        .await?
        .map(|row| row.get(0));
    owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES ('feature.chat_compliance',true) ON CONFLICT(key) DO UPDATE SET enabled=true", &[]).await?;
    let channel: i64 = owner
        .query_one("INSERT INTO chat_channels(kind,name,created_by,retention_days) VALUES ('channel',$1,1,1) RETURNING id", &[&format!("gofree-chat-cron-{}", std::process::id())])
        .await?
        .get(0);
    let result = run(&db, &owner, channel, recording).await;
    // Audit rows cascade with the channel; the append-only notary rows stay.
    owner
        .execute("DELETE FROM chat_channels WHERE id=$1", &[&channel])
        .await?;
    match prior {
        Some(enabled) => {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat_compliance'",
                    &[&enabled],
                )
                .await?
        }
        None => {
            owner
                .execute(
                    "DELETE FROM feature_toggles WHERE key='feature.chat_compliance'",
                    &[],
                )
                .await?
        }
    };
    result
}

async fn run(
    db: &Db,
    owner: &tokio_postgres::Client,
    channel: i64,
    recording: bool,
) -> Result<(), BoxError> {
    // Three messages from earlier days (past the 1-day retention) and one today.
    let mut ids = Vec::new();
    for (seq, (age, body)) in [
        ("3 days", "a"),
        ("3 days", "b"),
        ("2 days", "c"),
        ("0 days", "today"),
    ]
    .into_iter()
    .enumerate()
    {
        ids.push(owner.query_one("INSERT INTO chat_messages(channel_id,seq,author_id,body,created_at) VALUES ($1,$2::bigint,7,$3, date_trunc('day', now()) - $4::text::interval + interval '1 hour' * ($2::bigint + 1)) RETURNING id", &[&channel, &(seq as i64 + 1), &body, &age]).await?.get::<_, i64>(0));
    }
    // Today's message must really be today, whatever the hour.
    owner
        .execute(
            "UPDATE chat_messages SET created_at=now() WHERE id=$1",
            &[&ids[3]],
        )
        .await?;
    let notary_base: i64 = owner
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE action='chat.chain_notary'",
            &[],
        )
        .await?
        .get(0);
    let native = WorkerDatabase::new(&db.dsn)?.with_audit_keys(String::new(), HMAC.into());
    let mut phases = Vec::new();
    for (name, at, go_off, action) in PHASES {
        if recording {
            record_go_tick(db, at, go_off)?;
        } else {
            match action {
                Native::Nothing => {}
                Native::Anchor => setjoin_chat::workers::chain_anchor(&native).await?,
                Native::Purge => setjoin_chat::workers::purge_expired(&native).await?,
            }
        }
        phases.push(json!({"phase":name,"after":observe(owner,channel,&ids,notary_base).await?}));
    }
    let observation = json!({ "phases": phases });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/chat-b/goldens/cron-chat-tick.json");
    if recording {
        let anchored = &phases[1]["after"]["anchors"];
        let purged = &phases[2]["after"]["messages"];
        if anchored.as_array().is_none_or(|a| a.len() != 1)
            || purged != &json!([3])
            || phases[0]["after"]["anchors"] != json!([])
        {
            return Err(format!("unexpected Go cron effects: {observation}").into());
        }
        setjoin_conformance::golden::record(
            &path,
            &json!({"format":1,"case":"cron-chat-tick","go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        let golden: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        setjoin_conformance::golden::compare(&golden["observation"], &observation)?;
        println!("GOLDEN-REPLAY: cron chat-tick :: seed-plus-one-tick");
    }
    Ok(())
}

/// Row-level effects with ids replaced by message indexes (ids differ per run).
async fn observe(
    owner: &tokio_postgres::Client,
    channel: i64,
    ids: &[i64],
    notary_base: i64,
) -> Result<Value, BoxError> {
    let index = |id: i64| ids.iter().position(|m| *m == id);
    let anchors = owner.query("SELECT after_state::text FROM chat_audit_log WHERE channel_id=$1 AND action='chain.anchor' ORDER BY id", &[&channel]).await?;
    let anchors: Vec<Value> = anchors
        .iter()
        .map(|row| {
            let s: Value = serde_json::from_str(&row.get::<_, String>(0)).unwrap();
            json!({
                "idFrom": index(s["idFrom"].as_i64().unwrap_or(-1)),
                "idTo": index(s["idTo"].as_i64().unwrap_or(-1)),
                "count": s["count"],
                "digestLen": s["digest"].as_str().map(str::len),
            })
        })
        .collect();
    let messages: Vec<usize> = owner
        .query(
            "SELECT id FROM chat_messages WHERE channel_id=$1 ORDER BY id",
            &[&channel],
        )
        .await?
        .iter()
        .filter_map(|row| index(row.get(0)))
        .collect();
    let acts: Vec<Value> = owner.query("SELECT action, (after_state - 'digest' - '_checksum' - 'destroyedElems')::text FROM chat_audit_log WHERE channel_id=$1 AND action<>'chain.anchor' ORDER BY id", &[&channel]).await?
        .iter()
        .map(|row| json!({"action": row.get::<_, String>(0), "after": row.get::<_, Option<String>>(1).map(|v| strip_ids(serde_json::from_str(&v).unwrap(), ids))}))
        .collect();
    let notary: i64 = owner
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE action='chat.chain_notary'",
            &[],
        )
        .await?
        .get(0);
    let seq: i64 = owner
        .query_one(
            "SELECT last_purged_seq FROM chat_channels WHERE id=$1",
            &[&channel],
        )
        .await?
        .get(0);
    Ok(json!({
        "anchors": anchors,
        "messages": messages,
        "otherActs": acts,
        "notaryRowsAdded": notary - notary_base,
        "lastPurgedSeq": seq,
    }))
}

fn strip_ids(mut value: Value, ids: &[i64]) -> Value {
    for key in ["idFrom", "idTo"] {
        if let Some(id) = value.get(key).and_then(Value::as_i64) {
            value[key] = json!(ids.iter().position(|m| *m == id));
        }
    }
    value
}

fn record_go_tick(db: &Db, at: &str, go_off: &str) -> Result<(), BoxError> {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let folder = root.join("test-results/gofree-fix2-cron");
    std::fs::create_dir_all(&folder)?;
    let overlay = folder.join("overlay.json");
    std::fs::write(
        &overlay,
        serde_json::to_vec(
            &json!({"Replace":{"/src/mailserver/internal/cron/gofree_chat_cron_tick_test.go":"/src/server-rust/tests/conformance/chat-b/cron_tick_test.go.txt"}}),
        )?,
    )?;
    let name = format!("gofree-fix2-cron-oracle-{}", std::process::id());
    if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(ledger)?,
            "Planned {name}, local Docker, go cache {}/go-cache; assigned DB only; --rm",
            folder.display()
        )?;
    }
    let output = std::process::Command::new("docker")
        .args(["run", "--rm", "--name", &name, "--network", "host", "-v"])
        .arg(format!("{}:/src", root.display()))
        .args([
            "-v",
            &gofree_go_mod_mount(),
            "-w",
            "/src/mailserver",
            "-e",
        ])
        .arg(format!("GOFREE_CHAT_CRON_DSN={}", db.dsn))
        .args(["-e", &format!("GOFREE_CHAT_CRON_HMAC={HMAC}")])
        .args(["-e", &format!("GOFREE_CHAT_CRON_AT={at}")])
        .args(["-e", &format!("GO_WORKERS_OFF={go_off}")])
        .args([
            "-e",
            "GOMAXPROCS=1",
            "-e",
            "GOGC=50",
            "-e",
            "GOMEMLIMIT=768MiB",
        ])
        .args(["-e", "GOCACHE=/src/test-results/gofree-fix2-cron/go-cache"])
        .args([
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-vet=off",
            "-overlay=/src/test-results/gofree-fix2-cron/overlay.json",
            "./internal/cron",
            "-run",
            "^TestGoFreeChatCronTick$",
            "-count=1",
        ])
        .output()?;
    std::fs::write(
        folder.join("go-record.log"),
        [output.stdout.as_slice(), output.stderr.as_slice()].concat(),
    )?;
    if !output.status.success() {
        return Err(
            "frozen Go cron tick failed: see test-results/gofree-fix2-cron/go-record.log".into(),
        );
    }
    Ok(())
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
