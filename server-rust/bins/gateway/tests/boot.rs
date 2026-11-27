//! Boot is tested at its process boundary, on this ticket's disposable database.
use std::process::Stdio;
use tokio_postgres::NoTls;

fn dsn() -> Option<String> {
    let dsn = std::env::var("TEST_DB_DSN").ok();
    assert!(
        dsn.is_some() || std::env::var("REQUIRE_DB").as_deref() != Ok("1"),
        "TEST_DB_DSN is required"
    );
    dsn
}

#[tokio::test]
async fn unbaselined_database_refuses_boot_before_listening() {
    let Some(dsn) = dsn() else {
        eprintln!("BOOT-DB-SKIP (reason=no-dsn)");
        return;
    };
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    client
        .batch_execute("ALTER TABLE schema_migrations RENAME TO boot_saved_schema_migrations")
        .await
        .unwrap();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_setjoin-server"))
            .env_clear()
            .env("DB_DSN", &dsn)
            .env("GATEWAY_LISTEN", "127.0.0.1:0")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await;
    client
        .batch_execute("ALTER TABLE boot_saved_schema_migrations RENAME TO schema_migrations")
        .await
        .unwrap();
    drop(client);
    driver.await.unwrap().unwrap();
    let output = output.expect("unbaselined gateway kept running").unwrap();
    assert_eq!(output.status.code(), Some(1));
    let log = String::from_utf8(output.stderr).unwrap();
    assert!(
        log.contains("database has no schema — refusing to start"),
        "{log}"
    );
}

#[tokio::test]
async fn wave19_gateway_refuses_privileged_and_drifted_rls_and_boots_cleanly_on_app_worker_dsns() {
    let Some(owner_dsn) = dsn() else {
        eprintln!("BOOT-DB-SKIP (reason=no-dsn)");
        return;
    };
    let app_dsn = std::env::var("DB_APP_DSN").expect("DB_APP_DSN required");
    let worker_dsn = std::env::var("DB_WORKER_DSN").unwrap_or_else(|_| owner_dsn.clone());
    let (client, connection) = tokio_postgres::connect(&owner_dsn, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);

    let run_refusal = |label: &str, db_dsn: &str, db_worker: Option<&str>, expected_err: &str| {
        let label = label.to_owned();
        let db_dsn = db_dsn.to_owned();
        let db_worker = db_worker.map(str::to_owned);
        let expected_err = expected_err.to_owned();
        async move {
            let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_setjoin-server"));
            cmd.env_clear()
                .env("DB_DSN", &db_dsn)
                .env("DB_DIRECT_DSN", &db_dsn)
                .env("GATEWAY_LISTEN", "127.0.0.1:0")
                .env("NETWORK_MODE", "airgap")
                .env("S3_ENDPOINT", "127.0.0.1:9")
                .env("S3_ACCESS_KEY", "test")
                .env("S3_SECRET_KEY", "test")
                .kill_on_drop(true)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(w) = &db_worker {
                cmd.env("DB_WORKER_DSN", w);
            }
            let out = tokio::time::timeout(std::time::Duration::from_secs(15), cmd.output())
                .await
                .unwrap_or_else(|_| panic!("{label}: gateway kept running instead of refusing"))
                .unwrap();
            let log = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                out.status.code(),
                Some(1),
                "{label}: expected exit 1, stderr={log}"
            );
            assert!(
                log.contains("native-RLS boot check FAILED — refusing to start"),
                "{label}: missing refusal marker: {log}"
            );
            assert!(
                log.contains(&expected_err),
                "{label}: missing expected detail {expected_err:?}: {log}"
            );
        }
    };

    // 1. Superuser DB_DSN refuses boot.
    run_refusal(
        "superuser",
        &owner_dsn,
        Some(&worker_dsn),
        "connects as superuser",
    )
    .await;

    // 2. BYPASSRLS role (DB_WORKER_DSN as DB_DSN) refuses boot.
    if std::env::var("DB_WORKER_DSN").is_ok() {
        run_refusal("bypassrls", &worker_dsn, Some(&owner_dsn), "BYPASSRLS").await;
    }

    // 3. Shared app/worker DSN (or unset DB_WORKER_DSN) refuses boot.
    run_refusal(
        "shared-worker",
        &app_dsn,
        Some(&app_dsn),
        "DB_DSN and DB_WORKER_DSN share role",
    )
    .await;
    run_refusal(
        "unset-worker",
        &app_dsn,
        None,
        "DB_DSN and DB_WORKER_DSN share role",
    )
    .await;

    // 4. Direct FORCE-RLS table ownership refuses boot.
    let owned_tbl = format!("gw_boot_owned_547_{}", std::process::id());
    client
        .batch_execute(&format!(
            "DROP TABLE IF EXISTS {owned_tbl}; \
             CREATE TABLE {owned_tbl}(id int); \
             ALTER TABLE {owned_tbl} OWNER TO setjoin_app; \
             ALTER TABLE {owned_tbl} ENABLE ROW LEVEL SECURITY; \
             ALTER TABLE {owned_tbl} FORCE ROW LEVEL SECURITY;"
        ))
        .await
        .unwrap();
    run_refusal(
        "direct-owned",
        &app_dsn,
        Some(&worker_dsn),
        "owns FORCE-RLS table",
    )
    .await;
    client
        .batch_execute(&format!("DROP TABLE IF EXISTS {owned_tbl};"))
        .await
        .unwrap();

    // 5. Indirect FORCE-RLS table ownership via role membership refuses boot.
    let grp_role = format!("gw_boot_grp_547_{}", std::process::id());
    let grp_tbl = format!("gw_boot_ind_547_{}", std::process::id());
    client
        .batch_execute(&format!(
            "DROP ROLE IF EXISTS {grp_role}; \
             CREATE ROLE {grp_role} NOLOGIN; \
             CREATE TABLE {grp_tbl}(id int); \
             ALTER TABLE {grp_tbl} OWNER TO {grp_role}; \
             ALTER TABLE {grp_tbl} ENABLE ROW LEVEL SECURITY; \
             ALTER TABLE {grp_tbl} FORCE ROW LEVEL SECURITY; \
             GRANT {grp_role} TO setjoin_app;"
        ))
        .await
        .unwrap();
    run_refusal(
        "inherited-owned",
        &app_dsn,
        Some(&worker_dsn),
        "owns FORCE-RLS table",
    )
    .await;
    client
        .batch_execute(&format!(
            "REVOKE {grp_role} FROM setjoin_app; \
             DROP TABLE IF EXISTS {grp_tbl}; \
             DROP ROLE IF EXISTS {grp_role};"
        ))
        .await
        .unwrap();

    // 6. ENABLE ROW LEVEL SECURITY without FORCE refuses boot.
    let unforced_tbl = format!("gw_boot_unforced_547_{}", std::process::id());
    client
        .batch_execute(&format!(
            "DROP TABLE IF EXISTS {unforced_tbl}; \
             CREATE TABLE {unforced_tbl}(id int); \
             ALTER TABLE {unforced_tbl} ENABLE ROW LEVEL SECURITY; \
             CREATE POLICY p_{unforced_tbl} ON {unforced_tbl} USING (true);"
        ))
        .await
        .unwrap();
    run_refusal(
        "enable-without-force",
        &app_dsn,
        Some(&worker_dsn),
        "missing ENABLE or FORCE ROW LEVEL SECURITY",
    )
    .await;
    client
        .batch_execute(&format!("DROP TABLE IF EXISTS {unforced_tbl};"))
        .await
        .unwrap();

    // 7. Clean DB_APP_DSN + DB_WORKER_DSN passes native-RLS preflight and binds
    //    its HTTP listener (`/_gateway/healthz` -> 200 ok).
    let cfg_path = std::env::temp_dir().join(format!("gw-boot-547-{}.env", std::process::id()));
    std::fs::write(&cfg_path, "gw boot 547 fixture\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let s3_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let s3_addr = s3_listener.local_addr().unwrap();
    s3_listener.set_nonblocking(true).unwrap();
    let s3_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s3_stop_clone = s3_stop.clone();
    let s3_thread = std::thread::spawn(move || {
        use std::io::{Read, Write};
        while !s3_stop_clone.load(std::sync::atomic::Ordering::Acquire) {
            let Ok((mut stream, _)) = s3_listener.accept() else {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.contains("location") {
                "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>"
            } else if req.contains("uploads") {
                "<ListMultipartUploadsResult><Bucket>mailblobs</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>"
            } else {
                ""
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_addr = reserve.local_addr().unwrap();
    drop(reserve);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_setjoin-server"))
        .env_clear()
        .env("DB_DSN", &app_dsn)
        .env("DB_DIRECT_DSN", &app_dsn)
        .env("DB_WORKER_DSN", &worker_dsn)
        .env("DB_ENCRYPTION_KEY", "22".repeat(32))
        .env("CONFIG_PATH", &cfg_path)
        .env("GATEWAY_LISTEN", listen_addr.to_string())
        .env("NETWORK_MODE", "airgap")
        .env("MINIO_ENDPOINT", s3_addr.to_string())
        .env("S3_ACCESS_KEY", "test")
        .env("S3_SECRET_KEY", "test")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut ready = false;
    for _ in 0..100 {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(listen_addr).await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream
                .write_all(
                    b"GET /_gateway/healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            assert!(
                String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&resp)
            );
            ready = true;
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().await.unwrap();
            panic!(
                "gateway exited unexpectedly with {status}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
    s3_stop.store(true, std::sync::atomic::Ordering::Release);
    let _ = s3_thread.join();
    let _ = std::fs::remove_file(&cfg_path);
    assert!(
        ready,
        "clean gateway on DB_APP_DSN + DB_WORKER_DSN never became ready"
    );

    drop(client);
    driver.await.unwrap().unwrap();
}
