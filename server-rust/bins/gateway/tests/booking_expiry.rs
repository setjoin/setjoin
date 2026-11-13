//! Booking expiry worker (#296): seed plus one tick against frozen Go's real
//! `booking.Sweeper.Run` loop (overlay `tests/conformance/calendar/`), compared
//! on the committed rows. Record with `GOFREE_RECORD_BOOKING=1` and
//! `GOFREE_GO_SOURCE=<sha>`; replay runs one tick of the Rust worker.
mod common;
use common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::booking_worker::BookingExpiry;
use setjoin_pg::workers::WorkerDatabase;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SEED: &[(&str, &str, &str)] = &[
    // (marker, status, verification window)
    ("due", "pending", "now() - interval '1 hour'"),
    ("due-edge", "pending", "now() - interval '1 second'"),
    ("open", "pending", "now() + interval '1 hour'"),
    ("confirmed-past", "confirmed", "now() - interval '1 hour'"),
    ("cancelled-past", "cancelled", "now() - interval '1 hour'"),
    ("already-expired", "expired", "now() - interval '1 hour'"),
];

async fn observe(owner: &tokio_postgres::Client) -> Result<Value, BoxError> {
    let rows = owner
        .query(
            "SELECT booker_email || ':' || status FROM booking_requests WHERE booker_email LIKE 'gofree-sweep-%' ORDER BY booker_email",
            &[],
        )
        .await?;
    Ok(json!({"requests": rows.iter().map(|r| r.get::<_, String>(0)).collect::<Vec<_>>()}))
}

#[tokio::test]
async fn booking_expiry_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("booking-expiry") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "gofree-sweep").await?;
    owner
        .batch_execute("DELETE FROM booking_pages WHERE slug='gofree-sweep-page'")
        .await?;
    let page: i64 = owner
        .query_one(
            &format!("INSERT INTO booking_pages(mailbox_id,slug,title) VALUES({},'gofree-sweep-page','Sweep') RETURNING id", account.mailbox),
            &[],
        )
        .await?
        .get(0);
    for (n, (marker, status, window)) in SEED.iter().enumerate() {
        owner
            .batch_execute(&format!(
                "INSERT INTO booking_requests(page_id,mailbox_id,booker_email,booker_name,slot_start,slot_end,status,verify_token_hash,verify_expires_at) \
                 VALUES({page},{},'gofree-sweep-{marker}@sweep.test','x',now()+interval '{} days',now()+interval '{} days 1 hour','{status}','gofree-sweep-{marker}',{window})",
                account.mailbox,
                30 + n,
                30 + n
            ))
            .await?;
    }
    let before = observe(&owner).await?;
    let recording = std::env::var_os("GOFREE_RECORD_BOOKING").is_some();
    let result = async {
        if recording {
            record_go_tick(&db)?;
        } else {
            let worker = WorkerDatabase::new(&db.dsn)?;
            BookingExpiry::new(worker).tick().await?;
        }
        let after = observe(&owner).await?;
        let observation = json!({"before": before, "after": after});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/calendar/goldens/worker-booking-expiry.json");
        if recording {
            if observation["before"] == observation["after"] {
                return Err("Go's tick changed nothing".into());
            }
            let _ = std::fs::remove_file(&path);
            setjoin_conformance::golden::record(
                &path,
                &json!({"format":1,"case":"booking-expiry","go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
            )?;
        } else {
            let golden: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            setjoin_conformance::golden::compare(&golden["observation"], &observation)?;
            println!("GOLDEN-REPLAY: worker booking-expiry :: seed-plus-one-tick");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .batch_execute(&format!(
            "DELETE FROM booking_requests WHERE page_id={page}; DELETE FROM booking_pages WHERE id={page}"
        ))
        .await?;
    common::remove_blob_account(&owner, &account).await?;
    result
}

fn record_go_tick(db: &Db) -> Result<(), BoxError> {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let folder = root.join("test-results/gofree-cal1");
    std::fs::create_dir_all(&folder)?;
    let source = std::fs::read_to_string(root.join("mailserver/internal/booking/sweeper.go"))?;
    let patched = source.replace(
        "const sweepInterval = 10 * time.Minute",
        "var sweepInterval = 10 * time.Minute",
    );
    if patched == source {
        return Err("sweeper.go no longer declares the interval constant".into());
    }
    std::fs::write(folder.join("sweeper.go"), patched)?;
    std::fs::write(
        folder.join("overlay.json"),
        serde_json::to_vec(&json!({"Replace":{
            "/src/mailserver/internal/booking/sweeper.go":"/src/test-results/gofree-cal1/sweeper.go",
            "/src/mailserver/internal/booking/gofree_sweep_test.go":"/src/server-rust/tests/conformance/calendar/sweep_test.go.txt"
        }}))?,
    )?;
    let name = format!("gofree-cal1-sweep-{}", std::process::id());
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
        .arg(format!("GOFREE_SWEEP_DSN={}", db.dsn))
        .args([
            "-e",
            "GOMAXPROCS=1",
            "-e",
            "GOGC=50",
            "-e",
            "GOMEMLIMIT=768MiB",
        ])
        .args(["-e", "GOCACHE=/src/test-results/gofree-cal1/go-cache"])
        .args([
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-vet=off",
            "-overlay=/src/test-results/gofree-cal1/overlay.json",
            "./internal/booking",
            "-run",
            "^TestGoFreeBookingSweepTick$",
            "-count=1",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "frozen Go sweeper tick failed: {}",
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .join(" | ")
        )
        .into());
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
