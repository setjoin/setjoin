//! Pre-listener server initialization, preserving frozen Go's refusal classes.
use setjoin_pg::workers::{WorkerConnection, WorkerDatabase};
pub mod geoip;
mod secrets;
mod storage;
mod upgrade;

/// A refused boot is not always exit 1 in frozen Go: runGateway returns normally
/// on several initialization failures. Keep the process result beside the log.
#[derive(Debug)]
pub struct Refusal {
    pub exit_code: u8,
    pub message: String,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Refusal {}

fn log(level: &str, message: &str) {
    eprintln!("{}", serde_json::json!({"level":level,"msg":message}));
}
fn refuse(exit_code: u8, message: &str) -> Refusal {
    log("ERROR", message);
    Refusal {
        exit_code,
        message: message.into(),
    }
}
fn refuse_detail(exit_code: u8, message: &str, error: &str) -> Refusal {
    eprintln!(
        "{}",
        serde_json::json!({"level":"ERROR","msg":message,"error":error})
    );
    Refusal {
        exit_code,
        message: message.into(),
    }
}

/// No database means the established bare front door, with no local boot work.
/// Server deployments run these checks before constructing workers/listeners.
pub async fn run() -> Result<(), Refusal> {
    let Some(dsn) = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let configured = std::env::var("GEOIP_DB_PATH").unwrap_or_default();
    let path = if configured.is_empty() {
        "/var/lib/setjoin/geoip.mmdb"
    } else {
        &configured
    };
    let _ = geoip::ensure(
        std::path::Path::new(path),
        configured.is_empty(),
        &std::env::var("GEOIP_DB_SHA256").unwrap_or_default(),
        &std::env::var("GEO_BLOCK_COUNTRIES").unwrap_or_default(),
    )
    .await;
    let db = connect(&dsn)
        .await
        .map_err(|_| refuse(0, "database pool failed"))?;
    let worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| dsn.clone());
    let worker = connect(&worker_dsn)
        .await
        .map_err(|_| refuse(0, "worker database pool failed"))?;
    let owner_dsn = std::env::var("DB_OWNER_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| dsn.clone());
    let owner = connect(&owner_dsn)
        .await
        .map_err(|_| refuse(0, "owner database pool failed"))?;
    let rows = db
        .query(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            &[],
        )
        .await;
    let actual = match rows {
        Ok(rows) => rows[0].get::<_, i32>(0),
        Err(error) if error.contains("SQLSTATE 42P01") => 0,
        Err(_) => {
            return Err(refuse(
                1,
                "schema-version probe failed — cannot verify the database schema",
            ))
        }
    };
    let expected = setjoin_schema::MIGRATIONS.last().map_or(0, |m| m.0);
    if actual < expected {
        return Err(refuse(
            1,
            if actual == 0 {
                "database has no schema — refusing to start"
            } else {
                "database schema is behind this binary — refusing to start"
            },
        ));
    }
    log("INFO", "database schema version verified");
    let store =
        storage::Store::from_env().map_err(|_| refuse(0, "object storage client init failed"))?;
    assert_rls(&db)
        .await
        .map_err(|_| refuse(1, "native-RLS boot check FAILED — refusing to start"))?;
    if owner
        .query("SELECT create_monthly_partitions(1)", &[])
        .await
        .is_err()
    {
        log("ERROR", "startup: create_monthly_partitions failed — audit/auth inserts will hard-fail once a month boundary passes without its partition");
        return Err(refuse(
            0,
            "monthly partition ensure failed — refusing to start",
        ));
    }
    log(
        "INFO",
        "monthly partitions ready (current + next month, catalog-derived)",
    );
    let recovered = worker
        .query("SELECT startup_recovery()::text", &[])
        .await
        .map_err(|_| refuse(0, "database startup recovery failed — refusing to start"))?;
    log("INFO", "database startup recovery completed");
    report(&worker, &recovered[0].get::<_, String>(0)).await;
    if !std::env::var("WORM_MODE").unwrap_or_default().is_empty() {
        store
            .ensure_worm_bucket()
            .await
            .map_err(|_| refuse(0, "WORM bucket bootstrap failed — refusing to start"))?;
    }
    if store.abort_stale().await.is_err() {
        log("WARN", "startup: stale multipart abort encountered errors");
    }
    store.ping(&db).await;
    let mode = std::env::var("WORM_MODE").unwrap_or_default();
    let days = std::env::var("WORM_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2557);
    store
        .init_worm(&mode, days)
        .await
        .map_err(|error| Refusal {
            exit_code: 0,
            message: error,
        })?;
    let path = std::env::var("CONFIG_PATH")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/etc/mail/config.env".into());
    secrets::bootstrap(std::path::Path::new(&path))
        .map_err(|_| refuse(1, "secret bootstrap failed"))?;
    let flags = db.query("SELECT ft.key, ft.enabled, s.mode FROM feature_toggle_registry_state s LEFT JOIN feature_toggles ft ON true WHERE s.singleton ORDER BY ft.key", &[]).await
        .map_err(|error| refuse_detail(0,"toggle init failed", &error))?;
    if !flags
        .first()
        .is_some_and(|row| matches!(row.get::<_, String>(2).as_str(), "observe" | "enforce"))
    {
        return Err(refuse_detail(
            0,
            "toggle init failed",
            "toggle registry state missing or invalid",
        ));
    }
    for key in [
        "feature.conditional_access",
        "feature.device_trust_enforcement",
        "feature.device_lockdown",
        "dengbao.sod_mode",
        "feature.cae_runtime",
        "feature.token_binding",
        "feature.user_risk",
        "feature.smime_verify",
    ] {
        if !flags
            .iter()
            .any(|row| row.get::<_, Option<String>>(0).as_deref() == Some(key))
        {
            return Err(refuse(0, "security toggle seed check failed"));
        }
    }
    let upgraded = upgrade::run(&db)
        .await
        .map_err(|_| refuse(1, "identity connector secret startup validation failed"))?;
    if upgraded > 0 {
        log(
            "INFO",
            "legacy identity connector secrets encrypted at rest",
        );
    }
    log("INFO", "server boot checks completed");
    Ok(())
}

async fn report(db: &setjoin_pg::workers::WorkerConnection, result: &str) {
    use setjoin_pg::Type;
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct Summary {
        reset_outbound_queue: i64,
        repaired_folder_counts: i64,
        recovered_at: String,
    }
    let Ok(summary) = serde_json::from_str::<Summary>(result) else {
        log("WARN", "startup recovery report: failed to parse result");
        return;
    };
    if summary.reset_outbound_queue == 0 && summary.repaired_folder_counts == 0 {
        return;
    }
    let admin = db.query("SELECT u.id, mb.id, u.email FROM users u JOIN mailboxes mb ON mb.user_id=u.id AND mb.is_primary=TRUE WHERE u.is_local_admin=TRUE AND u.enabled=TRUE ORDER BY u.id LIMIT 1", &[]).await;
    let Ok(admin) = admin else {
        log("WARN", "startup recovery report: no admin user found");
        return;
    };
    let Some(admin) = admin.first() else {
        log("WARN", "startup recovery report: no admin user found");
        return;
    };
    let (user, mailbox, email) = (
        admin.get::<_, i64>(0),
        admin.get::<_, i64>(1),
        admin.get::<_, String>(2),
    );
    let (reset, repaired, at) = (
        summary.reset_outbound_queue,
        summary.repaired_folder_counts,
        summary.recovered_at,
    );
    let text = format!("Startup recovery detected inconsistent state and performed repairs:\n\n- Reset outbound queue items: {reset}\n- Repaired folder counters: {repaired}\n- Recovered at: {at}\n\nThis usually indicates an unclean shutdown or crash. Please review crash_events for details.\n");
    let html = format!("<p>Startup recovery detected inconsistent state and performed repairs:</p><ul><li>Reset outbound queue items: {reset}</li><li>Repaired folder counters: {repaired}</li><li>Recovered at: {at}</li></ul><p>This usually indicates an unclean shutdown or crash. Please review crash_events for details.</p>");
    let mut random = [0u8; 8];
    use ring::rand::SecureRandom;
    // Go randomID also formats its buffer if entropy fails.
    let _ = ring::rand::SystemRandom::new().fill(&mut random);
    let id = format!(
        "<{}@mailserver>",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let recipients = serde_json::json!([{"email":email}]).to_string();
    let size = text.len() as i64;
    let sent = db.query("SELECT send($1,$2,$3,$4,$5,$6::text::jsonb,'[]'::jsonb,'[]'::jsonb,$7,'','',$8,$9,$10,false,NULL)", &[
        (&user, Type::INT8), (&mailbox, Type::INT8), (&"internal://startup-report", Type::TEXT), (&id, Type::TEXT), (&email, Type::TEXT),
        (&recipients, Type::TEXT), (&"Mailserver Startup Recovery Report", Type::TEXT), (&text, Type::TEXT), (&html, Type::TEXT), (&size, Type::INT8),
    ]).await;
    if sent.is_err() {
        log("ERROR", "startup recovery report: failed to send email");
    } else {
        log("INFO", "startup recovery report sent");
    }
}

async fn assert_rls(db: &WorkerConnection) -> Result<(), String> {
    let role = db.query("SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user", &[]).await?;
    let owned = db.query("SELECT c.relname FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relforcerowsecurity AND c.relkind IN ('r','p') AND r.rolname=current_user ORDER BY c.relname", &[]).await?;
    let disabled = db.query("SELECT DISTINCT c.relname FROM pg_policy pol JOIN pg_class c ON c.oid=pol.polrelid WHERE c.relkind IN ('r','p') AND NOT c.relrowsecurity ORDER BY c.relname", &[]).await?;
    if role[0].get::<_, bool>(1) {
        log("INFO", "native-RLS boot check: runtime is a superuser identity — FORCE is inert (flip not live), skipping");
        return Ok(());
    }
    if role[0].get::<_, bool>(2) || !owned.is_empty() || !disabled.is_empty() {
        return Err("runtime role or policy catalog violates native-RLS invariants".into());
    }
    log("INFO", "native-RLS boot check: passed");
    Ok(())
}

async fn connect(dsn: &str) -> Result<WorkerConnection, String> {
    WorkerDatabase::new(dsn)
        .map_err(|e| e.to_string())?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        )
        .connect_session()
        .await
        .map_err(|e| e.to_string())
}
