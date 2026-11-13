//! User-risk worker (#314): seed plus one tick against frozen Go's real `computeUserRiskTick`
//! (overlay `tests/conformance/conditional-access/user_risk_tick_test.go.txt`), compared on the
//! committed `user_risk` and `session_revocations` rows and the `session_revoke` notifications,
//! with the feature toggle off (no-op) and on. Record with `GOFREE_RECORD_RISK=1` and
//! `GOFREE_GO_SOURCE=<sha>`; replay runs one tick of the Rust worker.
mod common;
use common::BoxError;
use serde_json::{Value, json};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::user_risk_worker::UserRisk;
use setjoin_pg::workers::WorkerDatabase;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn observe(owner: &tokio_postgres::Client, users: &[(i64, &str)]) -> Result<Value, BoxError> {
    let ids: Vec<i64> = users.iter().map(|u| u.0).collect();
    let mut risk = vec![];
    for r in owner
        .query("SELECT user_id, score::int, level, signals::text, remediated_at IS NOT NULL FROM user_risk WHERE user_id=ANY($1) ORDER BY user_id", &[&ids])
        .await?
    {
        let id: i64 = r.get(0);
        let name = users.iter().find(|u| u.0 == id).map(|u| u.1).unwrap_or("?");
        risk.push(json!({"user":name,"score":r.get::<_,i32>(1),"level":r.get::<_,String>(2),"signals":r.get::<_,String>(3),"remediated":r.get::<_,bool>(4)}));
    }
    let mut revocations = vec![];
    for r in owner
        .query("SELECT user_id, scope, reason FROM session_revocations WHERE user_id=ANY($1) ORDER BY user_id, id", &[&ids])
        .await?
    {
        let id: i64 = r.get(0);
        let name = users.iter().find(|u| u.0 == id).map(|u| u.1).unwrap_or("?");
        revocations.push(format!("{name}:{}:{}", r.get::<_, String>(1), r.get::<_, String>(2)));
    }
    Ok(json!({"user_risk": risk, "revocations": revocations}))
}

#[tokio::test]
async fn user_risk_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("user-risk") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let mut accounts = vec![];
    for label in [
        "risk-velocity",
        "risk-travel",
        "risk-high",
        "risk-old",
        "risk-quiet",
    ] {
        accounts.push((
            fixture::account(&owner, &format!("gofree-{label}")).await?,
            label,
        ));
    }
    let users: Vec<(i64, &str)> = accounts.iter().map(|(a, l)| (a.user, *l)).collect();
    let toggle: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.user_risk'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let emails: Vec<String> = {
        let mut out = vec![];
        for (a, _) in &accounts {
            out.push(
                owner
                    .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
                    .await?
                    .get(0),
            );
        }
        out
    };
    let mut seed = |email: &str, outcome: &str, country: Option<&str>, age: &str| {
        let sql = format!(
            "INSERT INTO auth_attempts(source_ip,target_username,outcome,geo_country,occurred_at) VALUES('203.0.113.5','{email}','{outcome}',{},now()-interval '{age}')",
            country.map_or("NULL".to_string(), |c| format!("'{c}'"))
        );
        sql
    };
    let mut statements = vec![];
    for n in 0..6 {
        statements.push(seed(
            &emails[0],
            "failure",
            None,
            &format!("{} minutes", 5 + n),
        ));
    }
    statements.push(seed(&emails[1], "success", Some("US"), "50 minutes"));
    statements.push(seed(&emails[1], "success", Some("DE"), "20 minutes"));
    for n in 0..6 {
        statements.push(seed(
            &emails[2],
            "failure",
            None,
            &format!("{} minutes", 5 + n),
        ));
    }
    statements.push(seed(&emails[2], "success", Some("US"), "50 minutes"));
    statements.push(seed(&emails[2], "success", Some("DE"), "20 minutes"));
    for n in 0..8 {
        statements.push(seed(
            &emails[3],
            "failure",
            None,
            &format!("{} hours", 30 + n),
        ));
    }
    statements.push(seed(&emails[4], "failure", None, "10 minutes"));
    owner.batch_execute(&statements.join(";")).await?;
    owner
        .execute(
            "DELETE FROM user_risk WHERE user_id=ANY($1)",
            &[&users.iter().map(|u| u.0).collect::<Vec<i64>>()],
        )
        .await?;
    let recording = std::env::var_os("GOFREE_RECORD_RISK").is_some();
    let result = async {
        let mut phases = vec![];
        for (phase, on) in [("toggle-off", false), ("toggle-on", true)] {
            owner
                .execute(
                    "INSERT INTO feature_toggles(key,enabled) VALUES('feature.user_risk',$1) ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled",
                    &[&on],
                )
                .await?;
            let before = observe(&owner, &users).await?;
            if recording {
                record_go_tick(&db)?;
            } else {
                UserRisk::new(WorkerDatabase::new(&db.dsn)?).tick().await?;
            }
            let after = observe(&owner, &users).await?;
            phases.push(json!({"phase":phase,"before":before,"after":after}));
        }
        if phases[0]["before"] != phases[0]["after"] {
            return Err("a tick with the toggle off changed state".into());
        }
        if phases[1]["before"] == phases[1]["after"] {
            return Err("a tick with the toggle on changed nothing".into());
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/conditional-access/goldens/worker-user-risk.json");
        if recording {
            let _ = std::fs::remove_file(&path);
            setjoin_conformance::golden::record(
                &path,
                &json!({"format":1,"case":"user-risk","go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":phases}),
            )?;
        } else {
            let golden: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            setjoin_conformance::golden::compare(&golden["observation"], &Value::Array(phases))?;
            println!("GOLDEN-REPLAY: worker user-risk :: seed-plus-one-tick");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    let ids: Vec<i64> = users.iter().map(|u| u.0).collect();
    owner
        .execute("DELETE FROM user_risk WHERE user_id=ANY($1)", &[&ids])
        .await?;
    owner
        .batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM session_revocations WHERE user_id IN ({}); DELETE FROM admin_audit_log WHERE target_type='user_risk' AND target_id IN ({0}); COMMIT;", ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",")))
        .await?;
    for email in &emails {
        owner
            .execute(
                "DELETE FROM auth_attempts WHERE target_username=$1",
                &[email],
            )
            .await?;
    }
    match toggle {
        Some(on) => {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.user_risk'",
                    &[&on],
                )
                .await?;
        }
        None => {
            owner
                .execute(
                    "DELETE FROM feature_toggles WHERE key='feature.user_risk'",
                    &[],
                )
                .await?;
        }
    }
    for (account, _) in &accounts {
        common::remove_blob_account(&owner, account).await?;
    }
    result
}

fn record_go_tick(db: &Db) -> Result<(), BoxError> {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let folder = root.join("test-results/gofree-ca2");
    std::fs::create_dir_all(&folder)?;
    std::fs::write(
        folder.join("overlay.json"),
        serde_json::to_vec(&json!({"Replace":{
            "/src/mailserver/internal/cron/gofree_risk_test.go":"/src/server-rust/tests/conformance/conditional-access/user_risk_tick_test.go.txt"
        }}))?,
    )?;
    let name = format!("gofree-ca2-risk-{}", std::process::id());
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
        .arg(format!("GOFREE_RISK_DSN={}", db.dsn))
        .args([
            "-e",
            "GOFREE_RISK_HMAC=",
            "-e",
            "GOMAXPROCS=1",
            "-e",
            "GOGC=50",
            "-e",
            "GOMEMLIMIT=768MiB",
        ])
        .args(["-e", "GOCACHE=/src/test-results/gofree-ca2/go-cache"])
        .args([
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-vet=off",
            "-overlay=/src/test-results/gofree-ca2/overlay.json",
            "./internal/cron",
            "-run",
            "^TestGoFreeUserRiskTick$",
            "-count=1",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "frozen Go user-risk tick failed: {}",
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
