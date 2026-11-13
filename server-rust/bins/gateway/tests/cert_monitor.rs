use chrono::{Duration, Utc};
use serde_json::Value;
use setjoin_gateway::cert_monitor::{CertMonitor, Certificate};
use setjoin_pg::cert_monitor::CertMonitorDatabase;
use std::sync::Arc;
use std::time::Duration as StdDuration;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn cert_monitor_matches_frozen_go_health_rows() {
    let _serial = SERIAL.lock().await;
    let Some(db) =
        setjoin_conformance::harness::Db::for_case("cert_monitor_matches_frozen_go_health_rows")
    else {
        return;
    };
    let dsn = db.dsn;
    let (client, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let monitor = Arc::new(CertMonitor::new(CertMonitorDatabase::new(&dsn).unwrap()));
    let golden: Vec<Value> = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/golden/go-cert-monitor.json"
        ))
        .unwrap(),
    )
    .unwrap();
    for (name, days, no_cert, dns_only) in [
        ("none", 0, true, false),
        ("expired", -2, false, false),
        ("seven", 7, false, false),
        ("fourteen", 14, false, true),
        ("thirty", 30, false, false),
        ("healthy", 31, false, false),
    ] {
        let before: i64 = client
            .query_one("SELECT COALESCE(max(id),0) FROM health_history", &[])
            .await
            .unwrap()
            .get(0);
        let now = Utc::now();
        let subject = format!("gofree-t10-rust-{name}.invalid");
        let not_after = now + Duration::days(days) + Duration::hours(12);
        let certs = if no_cert {
            vec![]
        } else {
            vec![
                Certificate {
                    not_after: now + Duration::days(100),
                    common_name: "later.invalid".into(),
                    dns_names: vec![],
                },
                Certificate {
                    not_after,
                    common_name: if dns_only {
                        String::new()
                    } else {
                        subject.clone()
                    },
                    dns_names: vec![subject.clone()],
                },
            ]
        };
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let worker = tokio::spawn({
            let monitor = monitor.clone();
            async move {
                monitor
                    .run_until(
                        move || certs.clone(),
                        StdDuration::from_secs(24 * 60 * 60),
                        async {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await
            }
        });
        let pattern = if no_cert {
            "no TLS certificates loaded".to_owned()
        } else {
            format!("%{subject}%")
        };
        let sql = "SELECT id, check_name, status, value::int, threshold::int, details FROM health_history WHERE id>$1 AND check_name='tls_cert' AND details LIKE $2 ORDER BY id DESC LIMIT 1";
        // Do not assert while the worker is alive: even a timeout or panic must
        // cancel and join it before looking up and deleting its exact row.
        let observed = tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                match client.query_opt(sql, &[&before, &pattern]).await {
                    Ok(Some(row)) => break Ok(row),
                    Ok(None) => tokio::time::sleep(StdDuration::from_millis(10)).await,
                    Err(err) => break Err(err),
                }
            }
        })
        .await;
        let _ = shutdown.send(());
        let joined = worker.await;
        let id: Option<i64> = match &observed {
            Ok(Ok(row)) => Some(row.get(0)),
            _ => client
                .query_opt(sql, &[&before, &pattern])
                .await
                .unwrap()
                .map(|row| row.get(0)),
        };
        if let Some(id) = id {
            client
                .execute("DELETE FROM health_history WHERE id=$1", &[&id])
                .await
                .unwrap();
        }
        joined.expect("worker panicked");
        let row = observed
            .expect("worker did not record health")
            .expect("database observation failed");
        let details: String = row.get(5);
        let normalized = details
            .replace(&subject, "SUBJECT")
            .replace(&not_after.format("%Y-%m-%d").to_string(), "DATE");
        let got = serde_json::json!({"case": name, "check_name": row.get::<_,String>(1), "status": row.get::<_,String>(2), "value": row.get::<_,i32>(3), "threshold": row.get::<_,i32>(4), "details": normalized});
        let want = golden.iter().find(|value| value["case"] == name).unwrap();
        assert_eq!(&got, want, "{name}");
    }
    drop(client);
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_cancels_in_flight_health_record() {
    let _serial = SERIAL.lock().await;
    let Some(db) =
        setjoin_conformance::harness::Db::for_case("shutdown_cancels_in_flight_health_record")
    else {
        return;
    };
    let (client, connection) = tokio_postgres::connect(&db.dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    // This lock delays only the monitor's INSERT until the test has requested
    // shutdown, without altering schema or touching other rows.
    client
        .batch_execute("BEGIN; LOCK TABLE health_history IN SHARE MODE")
        .await
        .unwrap();
    let monitor = Arc::new(CertMonitor::new(CertMonitorDatabase::new(&db.dsn).unwrap()));
    let subject = "gofree-t10-pending-cert.invalid";
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut worker = tokio::spawn(async move {
        monitor
            .run_until(
                || {
                    vec![Certificate {
                        not_after: Utc::now() + Duration::days(90),
                        common_name: subject.into(),
                        dns_names: vec![],
                    }]
                },
                StdDuration::from_secs(86400),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await;
    });
    let pending = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            client.query_one("SELECT pg_stat_clear_snapshot()", &[]).await.unwrap();
            let row = client.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'INSERT INTO health_history%' AND wait_event_type='Lock')", &[]).await.unwrap();
            if row.get::<_,bool>(0) { break }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    }).await.is_ok();
    let _ = shutdown.send(());
    let promptly_stopped = tokio::time::timeout(StdDuration::from_secs(2), &mut worker).await;
    client.batch_execute("ROLLBACK").await.unwrap();
    let joined_after_unlock = if promptly_stopped.is_err() {
        Some(tokio::time::timeout(StdDuration::from_secs(5), &mut worker).await)
    } else {
        None
    };
    // A cancelled blocked INSERT must not appear after releasing the lock.
    // If a broken implementation writes it anyway, delete its exact row.
    tokio::time::sleep(StdDuration::from_millis(200)).await;
    let pattern = format!("%{subject}%");
    let row = client.query_opt("SELECT id FROM health_history WHERE check_name='tls_cert' AND details LIKE $1 ORDER BY id DESC LIMIT 1", &[&pattern]).await.unwrap();
    if let Some(row) = &row {
        let id: i64 = row.get(0);
        client
            .execute("DELETE FROM health_history WHERE id=$1", &[&id])
            .await
            .unwrap();
    }
    assert!(pending, "monitor did not begin its database write");
    if let Some(result) = joined_after_unlock {
        result
            .expect("worker stuck after lock release")
            .expect("worker panicked");
    }
    promptly_stopped
        .expect("worker did not stop while insert was blocked")
        .expect("worker panicked");
    assert!(row.is_none(), "cancelled insert committed after shutdown");
    drop(client);
    driver.await.unwrap().unwrap();
}
