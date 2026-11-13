//! Public seed + one-boot process seam. Replay never invokes Go.
use std::process::Command;

/// The tests share one database and the oracle's fixture tables: libtest runs them on parallel
/// threads, so each takes this lock first (a poisoned lock only means an earlier test failed).
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn boot_probe_process() {
    if std::env::var("BOOT_PROBE_CHILD").as_deref() != Ok("1") {
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    if std::env::var("BOOT_GEOIP_SOURCE").as_deref() == Ok("cache") {
        runtime.block_on(setjoin_boot::geoip::ensure(
            std::path::Path::new(&std::env::var("GEOIP_DB_PATH").unwrap()),
            true,
            &std::env::var("GEOIP_DB_SHA256").unwrap_or_default(),
            &std::env::var("GEO_BLOCK_COUNTRIES").unwrap_or_default(),
        ));
        std::process::exit(0);
    }
    match runtime.block_on(setjoin_boot::run()) {
        Ok(()) => {
            if std::env::var("BOOT_INSPECT_SECRETS").as_deref() == Ok("1") {
                let values = runtime.block_on(inspect_fixture_secrets());
                println!("BOOT_DECRYPT {values}");
            }
            std::process::exit(0)
        }
        Err(refusal) => std::process::exit(i32::from(refusal.exit_code)),
    }
}

async fn inspect_fixture_secrets() -> serde_json::Value {
    use setjoin_config_secret::{keyring_from_env, ConfigSecretCodec};
    let db = setjoin_pg::operator::OperatorConnection::connect(&std::env::var("DB_DSN").unwrap())
        .await
        .unwrap();
    let deployment = db
        .query(
            "SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'",
            &[],
        )
        .await
        .unwrap();
    let codec =
        ConfigSecretCodec::new(keyring_from_env(&deployment[0].get::<_, String>(0)).unwrap())
            .unwrap();
    let rows=db.query("SELECT key,value::text FROM system_config WHERE key IN ('ad_sync_password_enc','ldap_sync_boot_enc','assist.api_key') ORDER BY key",&[]).await.unwrap();
    let mut values = serde_json::Map::new();
    for row in rows {
        let key = row.get::<_, String>(0);
        let value = codec
            .decrypt(&key, row.get::<_, String>(1).as_bytes())
            .unwrap();
        values.insert(key, serde_json::from_slice(&value).unwrap());
    }
    values.into()
}

#[test]
fn policy_table_with_rls_disabled_refuses_boot() {
    let _serial = serial();
    if std::env::var("TEST_DB_DSN").is_err() {
        assert_ne!(
            std::env::var("REQUIRE_DB").as_deref(),
            Ok("1"),
            "TEST_DB_DSN is required"
        );
        eprintln!("BOOT-DB-SKIP (reason=no-dsn)");
        return;
    }
    let code = r#"
import importlib.util,sys
from pathlib import Path
p=Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('oracle',p);o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
case={'id':'rls-disabled','request_app':True,
'before':'CREATE TABLE boot_rls_probe(id int); CREATE POLICY boot_policy ON boot_rls_probe USING (true)',
'after':'DROP TABLE boot_rls_probe'}
r=o.observe(case,sys.argv[2],False)
assert r['exit']==1 and ['ERROR','native-RLS boot check FAILED — refusing to start'] in r['events'],r
assert r['storage']==[],r
"#;
    let result = Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg("-c")
        .arg(code)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/oracle/oracle.py"
        ))
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn observe(case: serde_json::Value) -> serde_json::Value {
    let code = "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('oracle',sys.argv[1]);o=importlib.util.module_from_spec(s);s.loader.exec_module(o);print(json.dumps(o.observe(json.loads(sys.argv[3]),sys.argv[2],False)))";
    let result = Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg("-c")
        .arg(code)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/oracle/oracle.py"
        ))
        .arg(std::env::current_exe().unwrap())
        .arg(case.to_string())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
fn monthly_partition_fault_stops_boot_with_go_exit_class() {
    let _serial = serial();
    let r = observe(serde_json::json!({"id":"partition-missing",
        "before":"ALTER FUNCTION create_monthly_partitions(integer) RENAME TO boot_saved_partitions",
        "after":"ALTER FUNCTION boot_saved_partitions(integer) RENAME TO create_monthly_partitions"}));
    assert_eq!(r["exit"], 0);
    assert!(
        r["events"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!([
                "ERROR",
                "monthly partition ensure failed — refusing to start"
            ])),
        "{r}"
    );
    assert_eq!(r["storage"], serde_json::json!([]));
}

#[test]
fn one_boot_repairs_crashed_outbound_rows() {
    let _serial = serial();
    let r = observe(serde_json::json!({"id":"recovery-rows",
        "before":"INSERT INTO outbound_queue(message_id,from_addr,rcpt_addrs,raw_ref,status,queued_at) VALUES ('boot-recovery','boot@example.test',ARRAY['to@example.test'],'fixture','sending',now()-interval '10 minutes')",
        "after":"DELETE FROM outbound_queue WHERE message_id='boot-recovery'; DELETE FROM crash_events WHERE component='postgresql' AND description='Startup recovery detected inconsistent state (likely caused by unclean shutdown)'",
        "effects":"SELECT jsonb_build_object('status',status,'error',last_error) FROM outbound_queue WHERE message_id='boot-recovery'"}));
    assert_eq!(
        r["database"],
        serde_json::json!({"status":"pending","error":"reset by startup_recovery after crash"})
    );
    assert!(
        r["events"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!([
                "INFO",
                "database startup recovery completed"
            ])),
        "{r}"
    );
}

#[test]
fn recovery_report_reaches_first_admin_mailbox() {
    let _serial = serial();
    let r = observe(serde_json::json!({"id":"report",
        "before":"CREATE TABLE boot_account AS SELECT mk_account('boot-report') AS id; UPDATE users SET is_local_admin=true WHERE id=(SELECT user_id FROM mailboxes WHERE id=(SELECT id FROM boot_account)); INSERT INTO outbound_queue(message_id,from_addr,rcpt_addrs,raw_ref,status,queued_at) VALUES ('boot-report','boot@example.test',ARRAY['to@example.test'],'fixture','sending',now()-interval '10 minutes')",
        "after":"BEGIN; DELETE FROM outbound_queue WHERE message_id='boot-report'; DELETE FROM messages WHERE mailbox_id=(SELECT id FROM boot_account); DELETE FROM mailboxes WHERE id=(SELECT id FROM boot_account); DELETE FROM users WHERE display_name='boot-report'; DROP TABLE boot_account; DELETE FROM domains WHERE name='mk.test' AND NOT EXISTS (SELECT 1 FROM mailboxes m WHERE m.domain_id=domains.id); DELETE FROM crash_events WHERE component='postgresql'; COMMIT",
        "effects":"SELECT jsonb_build_object('reports',count(*)) FROM messages WHERE raw_ref='internal://startup-report' AND subject='Mailserver Startup Recovery Report'"}));
    assert!(r["database"]["reports"].as_i64().unwrap() > 0, "{r}");
    assert!(
        r["events"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(["INFO", "startup recovery report sent"])),
        "{r}"
    );
}

#[test]
fn replay_frozen_go_boot() {
    let _serial = serial();
    assert!(
        std::env::var("TEST_DB_DSN").is_ok(),
        "TEST_DB_DSN is required for the boot oracle"
    );
    let result = Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/oracle/oracle.py"
        ))
        .arg("replay")
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
