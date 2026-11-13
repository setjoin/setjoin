use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::ticket_keys::TicketKeys;
use setjoin_pg::ticket_keys::TicketKeyStore;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn codec() -> Arc<setjoin_config_secret::ConfigSecretCodec> {
    Arc::new(setjoin_config_secret::ConfigSecretCodec::new(setjoin_config_secret::ConfigSecretKeyring {
        deployment_id: "secfix3-ticket-deployment".into(),
        active_version: 1,
        active_key: b"secfix3-ticket-config-secret-key-0123456789".to_vec(),
        active_profile: setjoin_config_secret::CryptoProfile::Standard,
        retiring_keys: Default::default(),
    }).unwrap())
}
/// A generation pair sealed as the worker stores it (system_config secret envelope).
fn sealed(plain: &Value) -> String {
    String::from_utf8(codec().encrypt(setjoin_gateway::ticket_keys::CONFIG_KEY, plain.to_string().as_bytes()).unwrap()).unwrap()
}
fn opened(row: &str) -> Value {
    serde_json::from_slice(&codec().decrypt(setjoin_gateway::ticket_keys::CONFIG_KEY, row.as_bytes()).expect("row is a sealed envelope")).unwrap()
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type WorkerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
type WorkerControl = Arc<
    Mutex<
        Option<(
            Option<tokio::sync::oneshot::Sender<()>>,
            tokio::task::JoinHandle<WorkerResult>,
        )>,
    >,
>;

fn request_stop(control: &WorkerControl) {
    if let Some((stop, _)) = control.lock().unwrap().as_mut() {
        if let Some(stop) = stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn join_worker(control: &WorkerControl) -> WorkerResult {
    request_stop(control);
    let worker = control.lock().unwrap().take();
    if let Some((_, mut worker)) = worker {
        match tokio::time::timeout(Duration::from_secs(15), &mut worker).await {
            Ok(result) => result??,
            Err(error) => {
                worker.abort();
                let _ = worker.await;
                return Err(error.into());
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn ticket_rotation_matches_go_worker_oracle() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ticket_rotation_matches_go_worker_oracle") else {
        return;
    };
    let dsn = db.dsn;
    let (client, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let before = client.query_opt("SELECT value::text, encrypted, description, updated_at::text, updated_by FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap();
    let scenario_dsn = dsn.clone();
    let control: WorkerControl = Arc::new(Mutex::new(None));
    let scenario_control = control.clone();
    let result = tokio::spawn(async move {
        let (client, connection) = tokio_postgres::connect(&scenario_dsn, tokio_postgres::NoTls).await?;
        let scenario_driver = tokio::spawn(connection);
        let seed = json!({"current": STANDARD.encode([b'3'; 32]), "previous": STANDARD.encode([b'1'; 32])});
        client.execute("INSERT INTO system_config(key,value,encrypted,description,updated_at) VALUES('tls_session_ticket_keys',$1::text::jsonb,true,'ticket oracle',now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=EXCLUDED.encrypted,description=EXCLUDED.description,updated_at=EXCLUDED.updated_at", &[&sealed(&seed)]).await?;
        let store = TicketKeyStore::new(&scenario_dsn)?;
        let (observed, mut updates) = tokio::sync::mpsc::unbounded_channel();
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let done = Arc::new(tokio::sync::Notify::new());
        let worker_done = done.clone();
        let mut generation = 1u8;
        let worker = tokio::spawn(async move { let result = TicketKeys::run(
            store, Duration::from_millis(500), Some(codec()),
            move || { generation += 1; Ok([generation; 32]) },
            move |current, previous| { let _ = observed.send((current, previous, tokio::time::Instant::now())); },
            async { let _ = shutdown.await; },
        ).await; worker_done.notify_one(); result });
        *scenario_control.lock().unwrap() = Some((Some(stop), worker));
        let initial = tokio::time::timeout(Duration::from_secs(5), updates.recv()).await?.ok_or("missing initial keys")?;
        if (initial.0, initial.1) != ([b'3'; 32], Some([b'1'; 32])) { return Err("incorrect initial keys".into()); }
        let store = TicketKeyStore::new(&scenario_dsn)?;
        let startup: Value = opened(&store.load().await?.ok_or("missing startup keys")?);
        let rotated = tokio::time::timeout(Duration::from_secs(5), updates.recv()).await?.ok_or("missing rotated keys")?;
        if (rotated.0, rotated.1) != ([2; 32], Some([b'3'; 32])) { return Err("incorrect rotated keys".into()); }
        if rotated.2.duration_since(initial.2) < Duration::from_millis(500) { return Err("rotated before Go's interval elapsed".into()); }
        // The first rotated row, as the poll saw it: on a loaded host a later tick can land
        // before a second read, which would then show the second generation.
        let after: Value = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let row = store.load().await?.ok_or("missing rotated row")?;
                let value: Value = opened(&row);
                if value["current"] != seed["current"] { break Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(value); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        let row = client.query_one("SELECT value::text, encrypted FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await?;
        let current = STANDARD.decode(after["current"].as_str().ok_or("missing current")?)?;
        let actual = json!({"startup_unchanged": startup == seed, "current_changed": after["current"] != seed["current"], "current_bytes": current.len(), "previous_was_current": after["previous"] == seed["current"], "encrypted_label": row.get::<_, bool>(1)});
        // A second tick retains exactly one prior generation for resumption;
        // the startup current and previous are no longer supplied to TLS.
        let second = tokio::time::timeout(Duration::from_secs(5), updates.recv()).await?.ok_or("missing second rotation")?;
        if (second.0, second.1) != ([3; 32], Some([2; 32])) { return Err("older ticket key survived two rotations".into()); }
        if second.2.duration_since(initial.2) < Duration::from_secs(1) { return Err("second rotation occurred before Go's second tick".into()); }
        request_stop(&scenario_control);
        tokio::time::timeout(Duration::from_secs(15), done.notified()).await?;
        drop(client);
        scenario_driver.await??;
        Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(actual)
    }).await;
    let worker_result = join_worker(&control).await;
    if let Some(row) = before {
        client.execute("UPDATE system_config SET value=$1::text::jsonb, encrypted=$2, description=$3, updated_at=$4::text::timestamptz, updated_by=$5 WHERE key='tls_session_ticket_keys'", &[&row.get::<_, String>(0), &row.get::<_, bool>(1), &row.get::<_, Option<String>>(2), &row.get::<_, String>(3), &row.get::<_, Option<i64>>(4)]).await.unwrap();
    } else {
        client
            .execute(
                "DELETE FROM system_config WHERE key='tls_session_ticket_keys'",
                &[],
            )
            .await
            .unwrap();
    }
    drop(client);
    driver.await.unwrap().unwrap();
    worker_result.unwrap();
    let expected: Value =
        serde_json::from_str(include_str!("golden/go-ticket-rotation.json")).unwrap();
    assert_eq!(result.unwrap().unwrap(), expected);
}

#[tokio::test]
async fn ticket_worker_shutdown_cancels_a_blocked_write_before_returning() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ticket_worker_shutdown_cancels_a_blocked_write_before_returning")
    else {
        return;
    };
    let dsn = db.dsn;
    let (client, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let before = client.query_opt("SELECT value::text, encrypted, description, updated_at::text, updated_by FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap();
    let scenario_dsn = dsn.clone();
    let control: WorkerControl = Arc::new(Mutex::new(None));
    let scenario_control = control.clone();
    let result = tokio::spawn(async move {
        let (mut client, connection) = tokio_postgres::connect(&scenario_dsn, tokio_postgres::NoTls).await?;
        let scenario_driver = tokio::spawn(connection);
        let seed = json!({"current": STANDARD.encode([b'3'; 32]), "previous": STANDARD.encode([b'1'; 32])});
        client.execute("INSERT INTO system_config(key,value,encrypted,description,updated_at) VALUES('tls_session_ticket_keys',$1::text::jsonb,true,'ticket oracle',now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=EXCLUDED.encrypted,description=EXCLUDED.description,updated_at=EXCLUDED.updated_at", &[&sealed(&seed)]).await?;
        let (observed, mut updates) = tokio::sync::mpsc::unbounded_channel();
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let done = Arc::new(tokio::sync::Notify::new());
        let worker_done = done.clone();
        let worker = tokio::spawn(async move { let result = TicketKeys::run(TicketKeyStore::new(&scenario_dsn)?, Duration::from_millis(500), Some(codec()), || Ok([2; 32]), move |_, _| { let _ = observed.send(()); }, async { let _ = shutdown.await; }).await; worker_done.notify_one(); result });
        *scenario_control.lock().unwrap() = Some((Some(stop), worker));
        tokio::time::timeout(Duration::from_secs(5), updates.recv()).await?.ok_or("missing initial keys")?;
        let tx = client.transaction().await?;
        tx.batch_execute("LOCK TABLE system_config IN SHARE MODE").await?;
        tokio::time::timeout(Duration::from_secs(5), updates.recv()).await?.ok_or("missing rotation")?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tx.batch_execute("SELECT pg_stat_clear_snapshot()").await?;
                let blocked: bool = tx.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'INSERT INTO system_config (key,value,encrypted,%')", &[]).await?.get(0);
                if blocked { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }).await??;
        request_stop(&scenario_control);
        tokio::time::timeout(Duration::from_secs(5), done.notified()).await?;
        tx.rollback().await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let row: String = client.query_one("SELECT value::text FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await?.get(0);
        let unchanged = opened(&row) == seed;
        drop(client);
        scenario_driver.await??;
        Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(unchanged)
    }).await;
    let worker_result = join_worker(&control).await;
    if let Some(row) = before {
        client.execute("UPDATE system_config SET value=$1::text::jsonb, encrypted=$2, description=$3, updated_at=$4::text::timestamptz, updated_by=$5 WHERE key='tls_session_ticket_keys'", &[&row.get::<_, String>(0), &row.get::<_, bool>(1), &row.get::<_, Option<String>>(2), &row.get::<_, String>(3), &row.get::<_, Option<i64>>(4)]).await.unwrap();
    } else {
        client
            .execute(
                "DELETE FROM system_config WHERE key='tls_session_ticket_keys'",
                &[],
            )
            .await
            .unwrap();
    }
    drop(client);
    driver.await.unwrap().unwrap();
    worker_result.unwrap();
    assert!(
        result.unwrap().unwrap(),
        "blocked ticket write committed after shutdown"
    );
}

#[tokio::test]
async fn ticket_worker_fresh_key_and_entropy_failure_follow_go_startup() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ticket_worker_fresh_key_and_entropy_failure_follow_go_startup")
    else {
        return;
    };
    let dsn = db.dsn;
    let (client, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let before = client.query_opt("SELECT value::text, encrypted, description, updated_at::text, updated_by FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap();
    let scenario_dsn = dsn.clone();
    let control: WorkerControl = Arc::new(Mutex::new(None));
    let scenario_control = control.clone();
    let result = tokio::spawn(async move {
        let (client, connection) = tokio_postgres::connect(&scenario_dsn, tokio_postgres::NoTls).await?;
        let scenario_driver = tokio::spawn(connection);
        client.execute("DELETE FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await?;
        let (observed, mut updates) = tokio::sync::mpsc::unbounded_channel();
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let done = Arc::new(tokio::sync::Notify::new());
        let worker_done = done.clone();
        let store = TicketKeyStore::new(&scenario_dsn)?;
        let worker = tokio::spawn(async move {
            let result = TicketKeys::run(store, Duration::from_secs(60), Some(codec()), || Ok([9; 32]), move |current, previous| { let _ = observed.send((current, previous)); }, async { let _ = shutdown.await; }).await;
            worker_done.notify_one(); result
        });
        *scenario_control.lock().unwrap() = Some((Some(stop), worker));
        let initial = tokio::time::timeout(Duration::from_secs(5), updates.recv()).await?.ok_or("missing fresh key")?;
        // Owner-approved security fix 2026-11-05 (#503): fresh keys are sealed and persisted at once.
        let mut persisted = false;
        for _ in 0..200 {
            persisted = client.query_opt("SELECT 1 FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await?.is_some();
            if persisted { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        request_stop(&scenario_control);
        tokio::time::timeout(Duration::from_secs(15), done.notified()).await?;
        client.execute("INSERT INTO system_config(key,value,encrypted) VALUES ('tls_session_ticket_keys','\"[ENCRYPTED]\"'::jsonb,true) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", &[]).await?;
        let mut applied = None;
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let mut stop = Some(stop);
        let failed = TicketKeys::run(TicketKeyStore::new(&scenario_dsn)?, Duration::from_secs(60), Some(codec()), || Err(std::io::Error::other("entropy unavailable")), |current, previous| { applied = Some((current, previous)); if let Some(stop) = stop.take() { let _ = stop.send(()); } }, async { let _ = shutdown.await; }).await.is_err();
        let row: String = client.query_one("SELECT value::text FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await?.get(0);
        let valid = json!({"current": STANDARD.encode([b'3'; 32]), "previous": STANDARD.encode([b'1'; 32])});
        client.execute("UPDATE system_config SET value=$1::text::jsonb WHERE key='tls_session_ticket_keys'", &[&sealed(&valid)]).await?;
        let mut consumer_calls = 0usize;
        // The first 50 ms tick fails the run with Err; the 30 s shutdown is only a safety
        // valve, so a slow connect on a loaded host cannot end the run with Ok before the tick.
        let rotation_failed = TicketKeys::run(TicketKeyStore::new(&scenario_dsn)?, Duration::from_millis(50), Some(codec()), || Err(std::io::Error::other("entropy unavailable")), |_, _| consumer_calls += 1, tokio::time::sleep(Duration::from_secs(30))).await.is_err();
        let after_rotation: String = client.query_one("SELECT value::text FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await?.get(0);
        // Go's JSON decoder rejects a non-string previous field, so the whole
        // stored key set is unusable even when current is otherwise valid.
        let malformed = json!({"current": STANDARD.encode([b'3'; 32]), "previous": 7});
        client.execute("UPDATE system_config SET value=$1::text::jsonb WHERE key='tls_session_ticket_keys'", &[&sealed(&malformed)]).await?;
        let mut recovered = None;
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let mut stop = Some(stop);
        TicketKeys::run(TicketKeyStore::new(&scenario_dsn)?, Duration::from_secs(60), Some(codec()), || Ok([9; 32]), |current, previous| {
            recovered = Some((current, previous));
            let _ = stop.take().unwrap().send(());
        }, async { let _ = shutdown.await; }).await?;
        drop(client);
        scenario_driver.await??;
        Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(initial == ([9; 32], None) && persisted && failed && applied.is_none() && row == "\"[ENCRYPTED]\"" && rotation_failed && consumer_calls == 1 && opened(&after_rotation) == valid && recovered == Some(([9; 32], None)))
    }).await;
    let worker_result = join_worker(&control).await;
    if let Some(row) = before {
        client.execute("UPDATE system_config SET value=$1::text::jsonb, encrypted=$2, description=$3, updated_at=$4::text::timestamptz, updated_by=$5 WHERE key='tls_session_ticket_keys'", &[&row.get::<_, String>(0), &row.get::<_, bool>(1), &row.get::<_, Option<String>>(2), &row.get::<_, String>(3), &row.get::<_, Option<i64>>(4)]).await.unwrap();
    } else {
        client
            .execute(
                "DELETE FROM system_config WHERE key='tls_session_ticket_keys'",
                &[],
            )
            .await
            .unwrap();
    }
    drop(client);
    driver.await.unwrap().unwrap();
    worker_result.unwrap();
    assert!(result.unwrap().unwrap());
}

/// Owner-approved security fix 2026-11-05 (#503): persisted ticket keys are sealed
/// in the system_config secret envelope, as the row's `encrypted` marker claims. A
/// legacy plaintext row (what frozen Go wrote) is never trusted and is replaced.
#[tokio::test]
async fn persisted_ticket_keys_are_sealed_and_legacy_plaintext_is_replaced() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix3-ticket-sealed") else { return };
    let (client, connection) = tokio_postgres::connect(&db.dsn, tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let before = client.query_opt("SELECT value::text, encrypted, description, updated_at::text, updated_by FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap();
    let legacy = json!({"current": STANDARD.encode([b'3'; 32]), "previous": STANDARD.encode([b'1'; 32])});
    client.execute("INSERT INTO system_config(key,value,encrypted,description,updated_at) VALUES('tls_session_ticket_keys',$1::text::jsonb,true,'legacy',now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=true", &[&legacy.to_string()]).await.unwrap();
    let (observed, mut updates) = tokio::sync::mpsc::unbounded_channel();
    let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
    let store = TicketKeyStore::new(&db.dsn).unwrap();
    let worker = tokio::spawn(async move { TicketKeys::run(store, Duration::from_secs(60), Some(codec()), || Ok([9; 32]), move |c, p| { let _ = observed.send((c, p)); }, async { let _ = shutdown.await; }).await });
    let initial = tokio::time::timeout(Duration::from_secs(10), updates.recv()).await.unwrap().unwrap();
    // The startup save is awaited before the first timer tick; poll for the sealed row.
    let mut row = String::new();
    for _ in 0..200 {
        row = client.query_one("SELECT value::text FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap().get(0);
        if setjoin_config_secret::is_config_secret_envelope(row.as_bytes()) { break; }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let _ = stop.send(());
    worker.await.unwrap().unwrap();
    if let Some(r) = before {
        client.execute("UPDATE system_config SET value=$1::text::jsonb, encrypted=$2, description=$3, updated_at=$4::text::timestamptz, updated_by=$5 WHERE key='tls_session_ticket_keys'", &[&r.get::<_, String>(0), &r.get::<_, bool>(1), &r.get::<_, Option<String>>(2), &r.get::<_, String>(3), &r.get::<_, Option<i64>>(4)]).await.unwrap();
    } else {
        client.execute("DELETE FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap();
    }
    drop(client);
    driver.await.unwrap().unwrap();
    assert_eq!(initial, ([9; 32], None), "legacy plaintext keys were trusted");
    assert!(setjoin_config_secret::is_config_secret_envelope(row.as_bytes()), "row still plaintext: {row}");
    assert!(!row.contains(&STANDARD.encode([9u8; 32])), "key material visible in the stored row");
    assert_eq!(opened(&row)["current"], json!(STANDARD.encode([9u8; 32])));
}

/// Owner-approved security fix 2026-11-05 (#503): with no key material the worker
/// keeps fresh in-memory keys, never persists, and deletes a legacy plaintext row so
/// old Go keys do not linger; a sealed row is left in place.
#[tokio::test]
async fn without_a_codec_the_legacy_plaintext_row_is_deleted_and_a_sealed_row_kept() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix3-ticket-no-codec") else { return };
    let (client, connection) = tokio_postgres::connect(&db.dsn, tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let before = client.query_opt("SELECT value::text, encrypted, description, updated_at::text, updated_by FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap();
    let legacy = json!({"current": STANDARD.encode([b'3'; 32]), "previous": STANDARD.encode([b'1'; 32])});
    let mut outcome = Vec::new();
    for (label, row) in [("plaintext", legacy.to_string()), ("sealed", sealed(&legacy))] {
        client.execute("INSERT INTO system_config(key,value,encrypted,description,updated_at) VALUES('tls_session_ticket_keys',$1::text::jsonb,true,'legacy',now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=true", &[&row]).await.unwrap();
        let (observed, mut updates) = tokio::sync::mpsc::unbounded_channel();
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let store = TicketKeyStore::new(&db.dsn).unwrap();
        let worker = tokio::spawn(async move { TicketKeys::run(store, Duration::from_secs(60), None, || Ok([9; 32]), move |c, p| { let _ = observed.send((c, p)); }, async { let _ = shutdown.await; }).await });
        let initial = tokio::time::timeout(Duration::from_secs(10), updates.recv()).await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let remaining = client.query_opt("SELECT value::text FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap().map(|r| r.get::<_, String>(0));
        let _ = stop.send(());
        worker.await.unwrap().unwrap();
        outcome.push((label, initial, remaining));
    }
    client.execute("DELETE FROM system_config WHERE key='tls_session_ticket_keys'", &[]).await.unwrap();
    if let Some(r) = before {
        client.execute("INSERT INTO system_config(key,value,encrypted,description,updated_at,updated_by) VALUES('tls_session_ticket_keys',$1::text::jsonb,$2,$3,$4::text::timestamptz,$5)", &[&r.get::<_, String>(0), &r.get::<_, bool>(1), &r.get::<_, Option<String>>(2), &r.get::<_, String>(3), &r.get::<_, Option<i64>>(4)]).await.unwrap();
    }
    drop(client);
    driver.await.unwrap().unwrap();
    assert_eq!(outcome[0].1, ([9; 32], None), "legacy plaintext keys were trusted");
    assert!(outcome[0].2.is_none(), "legacy plaintext row lingers: {:?}", outcome[0].2);
    assert_eq!(outcome[1].1, ([9; 32], None));
    assert!(outcome[1].2.as_deref().is_some_and(|r| setjoin_config_secret::is_config_secret_envelope(r.as_bytes())), "sealed row must be kept");
}
