//! Frozen-Go seed-plus-one-tick oracle for the `dmarc-report` worker (#324). Recording runs
//! one `sendReports` pass of Go's real worker (overlay test) in the CI image; replay seeds the
//! same rows and runs ONE tick of the Rust worker. No Go process during replay.
mod common;
mod drain_oracle;
use drain_oracle::{BoxError, GoTick};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::dmarc_report::DmarcReport;
use setjoin_pg::workers::WorkerDatabase;

const HOST: &str = "mx.dmarc5-oracle.test";
const SUFFIX: &str = "dmarc5-oracle.test";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `(domain, report_uri, begin, end, total, none, pass, fail, temperror, permerror, policy, created)`
struct Row(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    i32,
    [i32; 5],
    Option<&'static str>,
    &'static str,
);
const OLD: &str = "2 hours";
const NEW: &str = "10 minutes";
const D1: (&str, &str) = ("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z");
const D2: (&str, &str) = ("2026-10-02T00:00:00Z", "2026-10-03T00:00:00Z");

fn seeds(case: &str) -> Vec<Row> {
    let rua = "mailto:rua@reports.test";
    match case {
        "mailto-basic" => vec![
            Row("one", rua, D1.0, D1.1, 4, [1, 3, 0, 0, 0], Some("one.dmarc5-oracle.test"), OLD),
            Row("one", rua, D2.0, D2.1, 5, [0, 4, 0, 1, 0], Some("one.dmarc5-oracle.test"), OLD),
        ],
        "failures-fail" => vec![Row(
            "two", rua, D1.0, D1.1, 7, [0, 3, 3, 1, 0], Some("Org & <Co> \"q\" 'a'"), OLD,
        )],
        "rua-forms" => vec![
            Row("size", "mailto:a@x.test!10m", D1.0, D1.1, 2, [0, 2, 0, 0, 0], None, OLD),
            Row("list", "https://x.test/r,mailto:b@x.test,mailto:c@x.test", D1.0, D1.1, 3, [0, 3, 0, 0, 0], None, OLD),
            Row("https", "https://only.test/r", D1.0, D1.1, 1, [0, 1, 0, 0, 0], None, OLD),
            Row("space", " mailto:d@x.test ", D1.0, D1.1, 1, [0, 1, 0, 0, 0], None, OLD),
            Row("empty", "", D1.0, D1.1, 1, [0, 1, 0, 0, 0], None, OLD),
        ],
        "recent-and-zero" => vec![
            Row("fresh", rua, D1.0, D1.1, 3, [0, 3, 0, 0, 0], None, NEW),
            Row("zero", rua, D1.0, D1.1, 0, [0, 0, 0, 0, 0], None, OLD),
        ],
        "two-uris" => vec![
            Row("twice", "mailto:first@x.test", D1.0, D1.1, 2, [0, 2, 0, 0, 0], None, OLD),
            Row("twice", "mailto:second@x.test", D2.0, D2.1, 2, [0, 2, 0, 0, 0], None, OLD),
        ],
        "null-policy" => vec![Row("plain", rua, D1.0, D1.1, 2, [0, 2, 0, 0, 0], None, OLD)],
        "mixed-age" => vec![
            Row("mixed", rua, D1.0, D1.1, 2, [0, 2, 0, 0, 0], None, OLD),
            Row("mixed", rua, D2.0, D2.1, 2, [0, 0, 2, 0, 0], None, NEW),
        ],
        "empty" => vec![],
        other => panic!("unknown case {other}"),
    }
}

/// Digit runs of ten or more (unix seconds and nanoseconds) become `<n>`.
fn digits(line: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for c in line.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_digit() {
            run.push(c);
            continue;
        }
        out.push_str(&if run.len() >= 10 { "<n>".to_owned() } else { run.clone() });
        run.clear();
        if c != '\0' {
            out.push(c);
        }
    }
    out
}

/// Run-specific times and counters are replaced; everything else stays byte-exact.
fn tidy(raw: &str) -> String {
    raw.split('\n')
        .map(|line| {
            if line.starts_with("Date: ") {
                "Date: <date>\r".to_owned()
            } else if line.contains("Message-ID:") || line.contains("report_id") || line.contains("boundary=") || line.starts_with("--dmarc-") {
                digits(line)
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn case(name: &str, omit_tick: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case(name) else {
        return Ok(());
    };
    let owner = db.connect().await?;
    // Go sweeps every row of the table: move foreign rows aside, put them back after.
    let stash: Vec<String> = owner
        .query("SELECT to_jsonb(r)::text FROM dmarc_reports r", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM dmarc_reports; COMMIT;")
        .await?;
    let result = async {
        for Row(domain, uri, begin, end, total, c, policy, age) in seeds(name) {
            let domain = format!("{domain}.{SUFFIX}");
            owner
                .execute(
                    &format!("INSERT INTO dmarc_reports (domain, report_uri, begin_time, end_time, total_count, count_none, count_pass, count_fail, count_temperror, count_permperror, policy_domain, created_at) \
                     VALUES ($1,$2,$3::text::timestamptz,$4::text::timestamptz,$5,$6,$7,$8,$9,$10,$11,now() - interval '{age}')"),
                    &[&domain, &uri, &begin, &end, &total, &c[0], &c[1], &c[2], &c[3], &c[4], &policy],
                )
                .await?;
        }
        let recording = std::env::var_os("GOFREE_RECORD_DRAIN").is_some() && !omit_tick;
        if recording {
            GoTick {
                package: "internal/smtp",
                overlay: "dmarc_report_tick_test.go.txt",
                test: "TestGoFreeDMARCReportTick",
                file: "gofree_dmarc_report_tick_test.go",
                env: vec![
                    ("GOFREE_DRAIN_DSN".into(), db.dsn.clone()),
                    ("GOFREE_DMARC_HOSTNAME".into(), HOST.into()),
                ],
                docker: vec![],
            }
            .run()?;
        } else if !omit_tick {
            DmarcReport::new(WorkerDatabase::new(&db.dsn)?, HOST.into()).tick().await;
        }
        let queued: Vec<Value> = owner
            .query(
                "SELECT jsonb_build_array(message_id, from_addr, rcpt_addrs, status, raw_ref, attempt_count)::text FROM outbound_queue WHERE from_addr = 'dmarc-reports@mx.dmarc5-oracle.test' ORDER BY id",
                &[],
            )
            .await?
            .iter()
            .map(|r| {
                let mut v: Value = serde_json::from_str(&r.get::<_, String>(0)).unwrap();
                let id = digits(v[0].as_str().unwrap());
                v[0] = json!(id);
                let raw = tidy(v[4].as_str().unwrap());
                v[4] = json!(raw);
                v
            })
            .collect();
        let remaining: Vec<Value> = owner
            .query(
                "SELECT jsonb_build_array(domain, report_uri, total_count, count_none, count_pass, count_fail, count_temperror, count_permperror, policy_domain)::text FROM dmarc_reports ORDER BY domain, report_uri, begin_time",
                &[],
            )
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)).unwrap())
            .collect();
        drain_oracle::settle(
            &format!("dmarc-report-{name}"),
            json!({"queued":queued,"remaining":remaining}),
            recording,
        )
    }
    .await;
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM dmarc_reports; DELETE FROM outbound_queue WHERE from_addr = 'dmarc-reports@mx.dmarc5-oracle.test'; COMMIT;")
        .await?;
    for row in &stash {
        owner
            .execute("INSERT INTO dmarc_reports SELECT * FROM jsonb_populate_record(NULL::dmarc_reports, $1::text::jsonb)", &[row])
            .await?;
    }
    result
}

macro_rules! cases {
    ($($fn:ident = $name:literal;)*) => {$(
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $fn() -> Result<(), BoxError> {
            case($name, false).await
        }
    )*};
}
cases! {
    mailto_basic_tick = "mailto-basic";
    failures_fail_tick = "failures-fail";
    rua_forms_tick = "rua-forms";
    recent_and_zero_tick = "recent-and-zero";
    two_uris_tick = "two-uris";
    null_policy_tick = "null-policy";
    mixed_age_tick = "mixed-age";
    empty_tick = "empty";
}

/// A worker that never ticks must fail the recorded observation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planted_no_tick_mutant_fails_the_golden() -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_RECORD_DRAIN").is_some() {
        return Ok(());
    }
    if Db::for_case("dmarc-report-mutant").is_none() {
        return Ok(());
    }
    match case("failures-fail", true).await {
        Err(_) => {
            eprintln!("MUTANT-REJECTED: dmarc-report :: no-tick");
            Ok(())
        }
        Ok(()) => Err("planted no-tick mutant survived".into()),
    }
}
