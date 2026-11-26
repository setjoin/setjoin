//! Pre-listener server initialization, preserving frozen Go's refusal classes
//! while surfacing Wave 1.7 (#545) Release N least-privilege RLS posture.
use setjoin_pg::rls_preflight::{inspect_rls_posture_worker, DsnRoleSummary, PostureContext};
pub use setjoin_pg::rls_preflight::{BootPosture, EnforcementMode};
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
pub async fn run() -> Result<BootPosture, Refusal> {
    run_with_mode(EnforcementMode::WarnReleaseN).await
}

/// Same pre-listener boot checks parameterized by Release N (`WarnReleaseN`)
/// vs Release N+1 (`FailClosedReleaseNPlus1`) enforcement mode.
pub async fn run_with_mode(mode: EnforcementMode) -> Result<BootPosture, Refusal> {
    let Some(dsn) = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()) else {
        return Ok(BootPosture::bare());
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
    let raw_worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty());
    let worker_dsn = raw_worker_dsn.clone().unwrap_or_else(|| dsn.clone());
    let worker = connect(&worker_dsn)
        .await
        .map_err(|_| refuse(0, "worker database pool failed"))?;
    let raw_owner_dsn = std::env::var("DB_OWNER_DSN").ok().filter(|s| !s.is_empty());
    let owner_dsn = raw_owner_dsn.clone().unwrap_or_else(|| dsn.clone());
    let owner = connect(&owner_dsn)
        .await
        .map_err(|_| refuse(0, "owner database pool failed"))?;
    let dsn_roles = DsnRoleSummary::from_dsns(
        Some(&dsn),
        raw_worker_dsn.as_deref(),
        raw_owner_dsn.as_deref(),
    );
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
    let boot_posture = assert_rls(&db, mode, dsn_roles)
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
    let mode = resolve_worm_mode_from_env();
    if !mode.is_empty() {
        store
            .ensure_worm_bucket()
            .await
            .map_err(|_| refuse(0, "WORM bucket bootstrap failed — refusing to start"))?;
    }
    if store.abort_stale().await.is_err() {
        log("WARN", "startup: stale multipart abort encountered errors");
    }
    store.ping(&db).await;
    let days = if mode.is_empty() {
        2557
    } else {
        let raw_days = env_last_ci("WORM_RETENTION_DAYS");
        parse_worm_retention_days(raw_days.as_deref())
            .map_err(|_| refuse(0, "invalid WORM_RETENTION_DAYS — refusing to start"))?
    };
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
    Ok(boot_posture)
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

async fn assert_rls(
    db: &WorkerConnection,
    mode: EnforcementMode,
    dsn_roles: DsnRoleSummary,
) -> Result<BootPosture, String> {
    let report =
        inspect_rls_posture_worker(db, PostureContext::RuntimeApp, Some(dsn_roles)).await?;
    if !report.hard_errors.is_empty() {
        for err in &report.hard_errors {
            log("ERROR", &format!("native-RLS boot check: {err}"));
        }
        return Err(report.hard_errors.join("; "));
    }
    if !report.warnings.is_empty() {
        match mode {
            EnforcementMode::WarnReleaseN => {
                for warning in &report.warnings {
                    log("WARN", &format!("native-RLS boot check: {warning}"));
                }
                return Ok(BootPosture::from_report(report, mode));
            }
            EnforcementMode::FailClosedReleaseNPlus1 => {
                for warning in &report.warnings {
                    log("ERROR", &format!("native-RLS boot check: {warning}"));
                }
                return Err(report.warnings.join("; "));
            }
        }
    }
    log("INFO", "native-RLS boot check: passed");
    Ok(BootPosture::from_report(report, mode))
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

fn env_last_ci(target: &str) -> Option<String> {
    std::env::vars().fold(None, |acc, (k, v)| {
        if k.eq_ignore_ascii_case(target) {
            Some(v)
        } else {
            acc
        }
    })
}

fn resolve_worm_mode_from_env() -> String {
    std::env::vars()
        .fold(None, |acc, (k, v)| {
            if k.eq_ignore_ascii_case("WORM_MODE") || k.eq_ignore_ascii_case("WORM__MODE") {
                Some(v)
            } else {
                acc
            }
        })
        .unwrap_or_default()
}

fn valid_digits_with_underscores(s: &str, allow_leading: bool, pred: fn(u8) -> bool) -> bool {
    let s = if allow_leading {
        s.strip_prefix('_').unwrap_or(s)
    } else {
        s
    };
    let bytes = s.as_bytes();
    let mut saw_digit = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'_' {
            if i == 0 || i + 1 == bytes.len() || bytes[i - 1] == b'_' || bytes[i + 1] == b'_' {
                return false;
            }
        } else if pred(b) {
            saw_digit = true;
        } else {
            return false;
        }
    }
    saw_digit
}

fn parse_go_hex_float64(s: &str) -> Option<f64> {
    let (neg, rest) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };
    let rest = rest
        .strip_prefix("0x")
        .or_else(|| rest.strip_prefix("0X"))?;
    let p_idx = rest.find(['p', 'P'])?;
    let mant_raw = &rest[..p_idx];
    let exp_raw = &rest[p_idx + 1..];
    let (exp_neg, exp_digits) = if let Some(r) = exp_raw.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = exp_raw.strip_prefix('+') {
        (false, r)
    } else {
        (false, exp_raw)
    };
    if !valid_digits_with_underscores(exp_digits, false, |b| b.is_ascii_digit()) {
        return None;
    }
    let exp_mag: i32 = exp_digits.replace('_', "").parse().ok()?;
    let exp_p = if exp_neg { -exp_mag } else { exp_mag };
    let (int_hex, frac_hex) = match mant_raw.split_once('.') {
        Some((i, f)) => {
            if !i.is_empty() && !valid_digits_with_underscores(i, true, |b| b.is_ascii_hexdigit()) {
                return None;
            }
            if !f.is_empty() && !valid_digits_with_underscores(f, false, |b| b.is_ascii_hexdigit())
            {
                return None;
            }
            (i, f)
        }
        None => {
            if !valid_digits_with_underscores(mant_raw, true, |b| b.is_ascii_hexdigit()) {
                return None;
            }
            (mant_raw, "")
        }
    };
    let int_clean = int_hex.replace('_', "");
    let frac_clean = frac_hex.replace('_', "");
    if int_clean.is_empty() && frac_clean.is_empty() {
        return None;
    }
    let mut val = 0.0_f64;
    for b in int_clean.bytes() {
        let d = (b as char).to_digit(16)? as f64;
        val = val * 16.0 + d;
    }
    let mut frac_scale = 1.0_f64 / 16.0;
    for b in frac_clean.bytes() {
        let d = (b as char).to_digit(16)? as f64;
        val += d * frac_scale;
        frac_scale /= 16.0;
    }
    let scaled = val * 2.0_f64.powi(exp_p);
    let result = if neg { -scaled } else { scaled };
    result.is_finite().then_some(result)
}

fn parse_go_float64(raw: &str) -> Option<f64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    if unsigned.starts_with("0x") || unsigned.starts_with("0X") {
        return parse_go_hex_float64(s);
    }
    let (mantissa, has_exp) = match unsigned.find(['e', 'E']) {
        Some(idx) => {
            let exp_raw = &unsigned[idx + 1..];
            let exp_digits = exp_raw.strip_prefix(['+', '-']).unwrap_or(exp_raw);
            if !valid_digits_with_underscores(exp_digits, false, |b| b.is_ascii_digit()) {
                return None;
            }
            (&unsigned[..idx], true)
        }
        None => (unsigned, false),
    };
    let _ = has_exp;
    match mantissa.split_once('.') {
        Some((int_part, frac_part)) => {
            if int_part.is_empty() && frac_part.is_empty() {
                return None;
            }
            if !int_part.is_empty()
                && !valid_digits_with_underscores(int_part, false, |b| b.is_ascii_digit())
            {
                return None;
            }
            if !frac_part.is_empty()
                && !valid_digits_with_underscores(frac_part, false, |b| b.is_ascii_digit())
            {
                return None;
            }
        }
        None => {
            if !valid_digits_with_underscores(mantissa, false, |b| b.is_ascii_digit()) {
                return None;
            }
        }
    }
    let v: f64 = s.replace('_', "").parse().ok()?;
    v.is_finite().then_some(v)
}

fn parse_worm_retention_days(raw: Option<&str>) -> Result<i64, String> {
    let Some(raw_str) = raw else {
        return Ok(2557);
    };
    let s = raw_str.trim();
    if s.is_empty() {
        return Err("WORM_RETENTION_DAYS is explicitly empty".into());
    }
    if let Ok(days) = s.parse::<i64>() {
        return Ok(days);
    }
    let v = parse_go_float64(s).ok_or_else(|| format!("invalid WORM_RETENTION_DAYS: {s:?}"))?;
    if !v.is_finite() || v < (i64::MIN as f64) || v >= 9_223_372_036_854_775_808.0 {
        return Err(format!("invalid WORM_RETENTION_DAYS: {s:?}"));
    }
    Ok(v as i64)
}

#[cfg(test)]
mod tests {
    use super::parse_worm_retention_days;

    #[test]
    fn worm_retention_days_matches_koanf_int_and_rejects_malformed() {
        assert_eq!(parse_worm_retention_days(None).unwrap(), 2557);
        assert!(parse_worm_retention_days(Some("")).is_err());
        assert_eq!(parse_worm_retention_days(Some("3650")).unwrap(), 3650);
        assert_eq!(
            parse_worm_retention_days(Some("9007199254740993")).unwrap(),
            9_007_199_254_740_993
        );
        assert_eq!(parse_worm_retention_days(Some("3650.0")).unwrap(), 3650);
        assert_eq!(parse_worm_retention_days(Some("1_000")).unwrap(), 1000);
        assert_eq!(parse_worm_retention_days(Some("0x1p+4")).unwrap(), 16);
        assert!(parse_worm_retention_days(Some("0x10")).is_err());
        assert!(parse_worm_retention_days(Some("bad")).is_err());
        assert!(parse_worm_retention_days(Some("NaN")).is_err());
    }
}
