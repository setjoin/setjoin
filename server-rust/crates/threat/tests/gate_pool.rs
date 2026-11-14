//! #367: pooled, bounded, fail-closed Gate worker statements.
use setjoin_pg::{ScopedExecutor, Timeouts};
use setjoin_threat::{Config, ConnectionMeta, Gate, ThreatAction, WorkerPools};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn dsn() -> String {
    std::env::var("TEST_DB_DSN").expect("TEST_DB_DSN (REQUIRE_DB lane)")
}

async fn connect(dsn: &str) -> tokio_postgres::Client {
    let (client, conn) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    client
}

/// A DSN whose sessions are recognisable in `pg_stat_activity`.
fn tagged(dsn: &str, app: &str) -> String {
    if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        let sep = if dsn.contains('?') { '&' } else { '?' };
        format!("{dsn}{sep}application_name={app}")
    } else {
        format!("{dsn} application_name={app}")
    }
}

fn pool(dsn: &str, size: usize, wait_ms: u64, statement_ms: u64) -> ScopedExecutor {
    ScopedExecutor::from_dsn_with(
        dsn,
        size,
        Timeouts {
            pool_wait: Duration::from_millis(wait_ms),
            create: Duration::from_secs(2),
            statement: Duration::from_millis(statement_ms),
        },
    )
    .unwrap()
}

fn unreachable() -> ScopedExecutor {
    pool("host=127.0.0.1 port=1 user=gate dbname=gate", 1, 100, 500)
}

fn quiet() -> Config {
    let mut config = Config::default();
    for key in [
        "threat_feed",
        "geo_block",
        "spray_detect",
        "captcha",
        "tarpit",
        "rate_limit",
        "conditional_access",
    ] {
        config.overrides.insert(format!("feature.{key}"), false);
    }
    config
}

fn with(mut config: Config, key: &str) -> Config {
    config.overrides.insert(format!("feature.{key}"), true);
    config
}

fn meta(ip: &str, user: &str) -> ConnectionMeta {
    ConnectionMeta {
        source_ip: ip.into(),
        username: user.into(),
        protocol: "ldap".into(),
        ..Default::default()
    }
}

fn keys(ip: &str, user: &str) -> Vec<String> {
    vec![
        format!("ip:{ip}"),
        format!("user:{user}"),
        format!("ip_user:{ip}:{user}"),
    ]
}

async fn forget(db: &tokio_postgres::Client, ip: &str, user: &str) {
    db.execute(
        "DELETE FROM auth_lockouts WHERE lockout_key = ANY($1)",
        &[&keys(ip, user)],
    )
    .await
    .unwrap();
    db.execute(
        "DELETE FROM auth_attempts WHERE source_ip = $1::text::inet",
        &[&ip],
    )
    .await
    .unwrap();
    db.execute(
        "DELETE FROM rate_limit_counters WHERE key = $1",
        &[&format!("auth:ldap:{ip}")],
    )
    .await
    .unwrap();
}

async fn escalated(db: &tokio_postgres::Client, ip: &str, user: &str) -> Vec<String> {
    db.query(
        "SELECT lockout_key FROM auth_lockouts WHERE lockout_key = ANY($1) ORDER BY lockout_key",
        &[&keys(ip, user)],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

async fn lock_waiters(db: &tokio_postgres::Client, app: &str) -> i64 {
    db.query_one(
        "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event_type='Lock'",
        &[&app],
    )
    .await
    .unwrap()
    .get(0)
}

async fn wait_for_waiters(db: &tokio_postgres::Client, app: &str, n: i64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while lock_waiters(db, app).await != n {
        assert!(
            Instant::now() < deadline,
            "{app}: expected {n} lock waiters"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Application name unique per process and run, so concurrent runs against a
/// shared cluster never observe each other's sessions.
fn uniq(base: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("{base}-{}-{nanos:08x}", std::process::id())
}

/// Wait (bounded) until a session of `app` in this database is actively running
/// a statement whose text contains `needle` (the specific workload, not an
/// incidental preliminary query such as the ip_rules check).
async fn wait_for_active(db: &tokio_postgres::Client, app: &str, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let n: i64 = db
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND state='active' AND pid<>pg_backend_pid() AND position($2 in query)>0",
                &[&app, &needle],
            )
            .await
            .unwrap()
            .get(0);
        if n > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{app}: no active `{needle}` statement"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Sets the shared stop flag on drop, so attackers end on every path
/// (including a failed assertion); each also self-limits by a deadline.
struct Stop(Arc<AtomicBool>);

impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// `n` attackers looping on `decide` from `ip` until the stop flag is set or
/// the deadline passes, so load stays outstanding for the whole victim probe.
/// Each task returns (decisions made, decisions allowed).
fn attackers(
    gate: &Arc<Gate>,
    n: usize,
    ip: &'static str,
    stop: &Arc<AtomicBool>,
) -> Vec<tokio::task::JoinHandle<(usize, usize)>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    (0..n)
        .map(|t| {
            let (gate, stop) = (gate.clone(), stop.clone());
            tokio::spawn(async move {
                let (mut total, mut allowed) = (0, 0);
                while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                    let user = format!("flood{t}-{total}@example.test");
                    if gate.decide(&meta(ip, &user), true).await.action == ThreatAction::Allow {
                        allowed += 1;
                    }
                    total += 1;
                }
                (total, allowed)
            })
        })
        .collect()
}

/// Stop the attackers and join them (bounded); returns summed (total, allowed).
async fn stop_attackers(
    stop: &Stop,
    tasks: Vec<tokio::task::JoinHandle<(usize, usize)>>,
) -> (usize, usize) {
    stop.0.store(true, Ordering::SeqCst);
    let (mut total, mut allowed) = (0, 0);
    for task in tasks {
        let (t, a) = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("attacker did not stop")
            .unwrap();
        total += t;
        allowed += a;
    }
    (total, allowed)
}

async fn load(exec: ScopedExecutor, worker: WorkerPools, config: Config) -> std::sync::Arc<Gate> {
    Gate::load(exec, worker, config, None).await.unwrap()
}

#[tokio::test]
async fn gate_reuses_pooled_worker_connections() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let app = uniq("gate367-reuse");
    let app = app.as_str();
    let db = connect(&dsn).await;
    let (ip, user) = ("198.18.36.7", "gate367-reuse@example.test");
    forget(&db, ip, user).await;
    let worker = WorkerPools {
        check: pool(&tagged(&dsn, app), 1, 1000, 2000),
        record: pool(&tagged(&dsn, app), 1, 1000, 2000),
    };
    let gate = load(ScopedExecutor::from_dsn(&dsn, 2).unwrap(), worker, quiet()).await;
    let pids = || async {
        db.query(
            "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 ORDER BY pid",
            &[&app],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<_, i32>(0))
        .collect::<Vec<_>>()
    };
    gate.decide(&meta(ip, user), true).await;
    gate.record(&meta(ip, user), false, 0).await;
    let first = pids().await;
    for _ in 0..10 {
        gate.decide(&meta(ip, user), true).await;
        gate.record(&meta(ip, user), false, 0).await;
    }
    gate.record(&meta(ip, user), true, 0).await;
    let after = pids().await;
    forget(&db, ip, user).await;
    assert_eq!(
        first.len(),
        2,
        "one pooled check and one pooled record connection"
    );
    assert_eq!(
        after, first,
        "every Gate DB call reused the pooled connections"
    );
}

#[tokio::test]
async fn exhausted_check_pool_rejects_lockout_and_recovers() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let app = uniq("gate367-exhaust");
    let app = app.as_str();
    let (db, probe) = (connect(&dsn).await, connect(&dsn).await);
    let (ip, user) = ("198.18.36.8", "gate367-exhaust@example.test");
    forget(&db, ip, user).await;
    let worker = WorkerPools {
        check: pool(&tagged(&dsn, app), 1, 300, 10_000),
        record: pool(&tagged(&dsn, &format!("{app}-rec")), 1, 300, 500),
    };
    let gate = load(ScopedExecutor::from_dsn(&dsn, 2).unwrap(), worker, quiet()).await;
    assert_eq!(
        gate.decide(&meta(ip, user), true).await.action,
        ThreatAction::Allow
    );
    db.batch_execute("BEGIN; LOCK TABLE auth_lockouts IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let holder = {
        let gate = gate.clone();
        tokio::spawn(async move { gate.decide(&meta(ip, user), true).await.action })
    };
    wait_for_waiters(&probe, app, 1).await;
    let started = Instant::now();
    let exhausted =
        tokio::time::timeout(Duration::from_secs(3), gate.decide(&meta(ip, user), true)).await;
    let waited = started.elapsed();
    let recorded = tokio::time::timeout(
        Duration::from_secs(3),
        gate.record(&meta(ip, user), false, 0),
    )
    .await;
    db.batch_execute("ROLLBACK").await.unwrap();
    let held = holder.await.unwrap();
    let recovered = gate.decide(&meta(ip, user), true).await.action;
    forget(&db, ip, user).await;
    let exhausted = exhausted.expect("pool exhaustion must not hang admission");
    assert_eq!(exhausted.action, ThreatAction::Reject);
    assert_eq!(
        exhausted.reason, "lockout_unavailable",
        "exhaustion must not skip lockout"
    );
    assert!(
        waited >= Duration::from_millis(300),
        "test did not exercise the pool wait"
    );
    assert!(recorded.is_ok(), "record must stay bounded");
    assert_eq!(held, ThreatAction::Allow);
    assert_eq!(
        recovered,
        ThreatAction::Allow,
        "the pool recovers after exhaustion"
    );
}

#[tokio::test]
async fn timed_out_lockout_check_is_cancelled_server_side() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let app = uniq("gate367-cancel");
    let app = app.as_str();
    let (db, probe) = (connect(&dsn).await, connect(&dsn).await);
    let (ip, user) = ("198.18.36.9", "gate367-cancel@example.test");
    forget(&db, ip, user).await;
    let worker = WorkerPools {
        check: pool(&tagged(&dsn, app), 1, 200, 300),
        record: pool(&dsn, 1, 200, 300),
    };
    let gate = load(ScopedExecutor::from_dsn(&dsn, 2).unwrap(), worker, quiet()).await;
    db.batch_execute("BEGIN; LOCK TABLE auth_lockouts IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let decision = gate.decide(&meta(ip, user), true).await;
    // The lock is still held: a surviving waiter would mean no CancelRequest.
    wait_for_waiters(&probe, app, 0).await;
    db.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(decision.reason, "lockout_unavailable");
}

#[tokio::test]
async fn unreachable_worker_boots_and_fails_closed() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let worker = WorkerPools {
        check: unreachable(),
        record: unreachable(),
    };
    let gate = load(
        ScopedExecutor::from_dsn(&dsn, 2).unwrap(),
        worker,
        with(quiet(), "spray_detect"),
    )
    .await;
    let locked = gate
        .decide(&meta("198.18.36.10", "gate367-down@example.test"), true)
        .await;
    assert_eq!(
        (locked.action, locked.reason.as_str()),
        (ThreatAction::Reject, "lockout_unavailable")
    );
    let spray = gate.decide(&meta("198.18.36.10", ""), true).await;
    assert_eq!(
        (spray.action, spray.reason.as_str()),
        (ThreatAction::Reject, "spray_unavailable")
    );
}

#[tokio::test]
async fn boot_probe_refuses_credential_without_lockout_execute() {
    let _s = SERIAL.lock().await;
    let app = std::env::var("DB_APP_DSN").expect("DB_APP_DSN (REQUIRE_DB lane)");
    let refused = Gate::load(
        ScopedExecutor::from_dsn(&dsn(), 2).unwrap(),
        WorkerPools::from_dsn(&app).unwrap(),
        quiet(),
        None,
    )
    .await
    .err()
    .expect("setjoin_app must not pass the worker probe")
    .to_string();
    assert!(refused.contains("lockout"), "{refused}");
}

#[tokio::test]
async fn reserved_record_pool_escalates_while_check_pool_is_saturated() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let app = uniq("gate367-reserve");
    let app = app.as_str();
    let (db, probe) = (connect(&dsn).await, connect(&dsn).await);
    let (ip, user) = ("198.18.36.11", "gate367-reserve@example.test");
    forget(&db, ip, user).await;
    let worker = WorkerPools {
        check: pool(&tagged(&dsn, app), 1, 200, 10_000),
        record: pool(&dsn, 1, 1000, 2000),
    };
    let gate = load(
        pool(&dsn, 2, 1000, 300),
        worker,
        with(quiet(), "spray_detect"),
    )
    .await;
    db.batch_execute("BEGIN; LOCK TABLE auth_attempts IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let holder = {
        let gate = gate.clone();
        tokio::spawn(async move { gate.decide(&meta("198.18.36.12", ""), true).await.action })
    };
    wait_for_waiters(&probe, app, 1).await;
    let saturated = gate.decide(&meta(ip, user), true).await;
    gate.record(&meta(ip, user), false, 0).await;
    let counted = escalated(&probe, ip, user).await;
    db.batch_execute("ROLLBACK").await.unwrap();
    holder.await.unwrap();
    forget(&db, ip, user).await;
    assert_eq!(saturated.reason, "lockout_unavailable");
    assert_eq!(
        counted.len(),
        3,
        "all three keys escalated on the reserved pool: {counted:?}"
    );
}

#[tokio::test]
async fn rate_limited_flood_does_not_starve_another_source() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let app = uniq("gate367-flood");
    let app = app.as_str();
    let db = connect(&dsn).await;
    let (attacker, victim, user) = (
        "198.18.36.20",
        "198.18.36.21",
        "gate367-victim@example.test",
    );
    forget(&db, attacker, "").await;
    forget(&db, victim, user).await;
    let mut config = with(quiet(), "rate_limit");
    config.rate_limit_per_min = 3;
    let gate = load(
        ScopedExecutor::from_dsn(&tagged(&dsn, app), 8).unwrap(),
        WorkerPools::from_dsn(&tagged(&dsn, app)).unwrap(),
        config,
    )
    .await;
    let stop = Stop(Arc::new(AtomicBool::new(false)));
    let flood = attackers(&gate, 64, attacker, &stop.0);
    // The attacker's own rate-limit statement must be in flight, and the
    // attackers keep looping until the victim's decision has been measured.
    wait_for_active(&db, app, "rate_limit_counters").await;
    let started = Instant::now();
    let decision = gate.decide(&meta(victim, user), true).await;
    gate.record(&meta(victim, user), false, 0).await;
    let elapsed = started.elapsed();
    let (total, allowed) = stop_attackers(&stop, flood).await;
    let counted = escalated(&db, victim, user).await;
    forget(&db, attacker, "").await;
    forget(&db, victim, user).await;
    assert_eq!(decision.action, ThreatAction::Allow, "{decision:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "victim waited {elapsed:?}"
    );
    assert!(total > 64, "attackers did not keep load up: {total}");
    assert!(allowed <= 3, "flood passed the rate limit {allowed} times");
    assert_eq!(counted.len(), 3, "victim failure counted on all keys");
}

#[tokio::test]
async fn large_attacker_history_does_not_block_other_sources() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let app = uniq("gate367-flood");
    let app = app.as_str();
    let db = connect(&dsn).await;
    let (attacker, victim) = ("198.18.36.30", "198.18.36.31");
    db.batch_execute("SELECT create_monthly_partitions()")
        .await
        .unwrap();
    forget(&db, attacker, "").await;
    db.batch_execute(
        "INSERT INTO auth_attempts(source_ip,target_username,protocol,outcome) SELECT '198.18.36.30'::inet,'spray'||g||'@example.test','ldap','failure' FROM generate_series(1,200000) g; ANALYZE auth_attempts",
    )
    .await
    .unwrap();
    let mut config = with(quiet(), "spray_detect");
    config.spray_max_users = 1_000_000;
    let gate = load(
        ScopedExecutor::from_dsn(&tagged(&dsn, app), 8).unwrap(),
        WorkerPools::from_dsn(&tagged(&dsn, app)).unwrap(),
        config,
    )
    .await;
    let stop = Stop(Arc::new(AtomicBool::new(false)));
    let load_tasks = attackers(&gate, 16, attacker, &stop.0);
    // The slow spray statement itself must be running under the victim probe.
    wait_for_active(&db, app, "detect_spray").await;
    let started = Instant::now();
    let decision = gate
        .decide(&meta(victim, "gate367-big@example.test"), true)
        .await;
    let elapsed = started.elapsed();
    let (total, _) = stop_attackers(&stop, load_tasks).await;
    forget(&db, attacker, "").await;
    forget(&db, victim, "gate367-big@example.test").await;
    assert!(total >= 16, "attackers did not keep load up: {total}");
    assert_eq!(decision.action, ThreatAction::Allow, "{decision:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "victim waited {elapsed:?}"
    );
}

#[tokio::test]
async fn oversized_username_still_escalates_ip_key() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let db = connect(&dsn).await;
    let ip = "198.18.36.40";
    let user: String = (0..4096u32)
        .map(|i| char::from(b'a' + ((i.wrapping_mul(7919) ^ (i >> 3)) % 26) as u8))
        .collect::<String>()
        + "@example.test";
    forget(&db, ip, &user).await;
    let gate = load(
        ScopedExecutor::from_dsn(&dsn, 2).unwrap(),
        WorkerPools::from_dsn(&dsn).unwrap(),
        quiet(),
    )
    .await;
    tokio::time::timeout(
        Duration::from_secs(5),
        gate.record(&meta(ip, &user), false, 0),
    )
    .await
    .expect("bounded");
    let counted = escalated(&db, ip, &user).await;
    forget(&db, ip, &user).await;
    assert!(
        counted.contains(&format!("ip:{ip}")),
        "ip key not escalated: {counted:?}"
    );
}

#[tokio::test]
async fn nul_username_rejects_instead_of_skipping_lockout() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let gate = load(
        ScopedExecutor::from_dsn(&dsn, 2).unwrap(),
        WorkerPools::from_dsn(&dsn).unwrap(),
        quiet(),
    )
    .await;
    let decision = gate
        .decide(&meta("198.18.36.41", "nul\0user@example.test"), true)
        .await;
    assert_eq!(decision.action, ThreatAction::Reject);
    assert_eq!(decision.reason, "lockout_unavailable");
}

#[tokio::test]
async fn unknown_source_ip_is_rejected() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let gate = load(
        ScopedExecutor::from_dsn(&dsn, 2).unwrap(),
        WorkerPools::from_dsn(&dsn).unwrap(),
        with(quiet(), "spray_detect"),
    )
    .await;
    // IMAP sends "unknown" without a peer (imap/src/auth.rs:125-128). The
    // first ::inet cast is ip_rules, which now fails closed before spray.
    let decision = gate
        .decide(&meta("unknown", "gate367-unknown@example.test"), true)
        .await;
    assert_eq!(decision.action, ThreatAction::Reject);
    assert_eq!(decision.reason, "ip_rules_unavailable");
}

#[tokio::test]
async fn spray_detected_arms_audits_and_notifies() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let db = connect(&dsn).await;
    let ip = "198.18.36.50";
    db.batch_execute("SELECT create_monthly_partitions()")
        .await
        .unwrap();
    forget(&db, ip, "").await;
    db.batch_execute(
        "INSERT INTO auth_attempts(source_ip,target_username,protocol,outcome) SELECT '198.18.36.50'::inet,'s'||g||'@example.test','ldap','failure' FROM generate_series(1,5) g",
    )
    .await
    .unwrap();
    let audits = || async {
        db.query_one(
            "SELECT count(*) FROM audit_log WHERE event_type='spray_detected' AND source_ip='198.18.36.50'::inet",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0)
    };
    let before = audits().await;
    let mut listener = setjoin_pg::workers::DirectListener::connect(&dsn, "alert:spray")
        .await
        .unwrap();
    let mut config = with(quiet(), "spray_detect");
    config.spray_max_users = 5;
    let gate = load(
        ScopedExecutor::from_dsn(&dsn, 2).unwrap(),
        WorkerPools::from_dsn(&dsn).unwrap(),
        config,
    )
    .await;
    let decision = gate.decide(&meta(ip, ""), true).await;
    let note = tokio::time::timeout(Duration::from_secs(5), listener.recv()).await;
    let armed: i64 = db
        .query_one(
            "SELECT count(*) FROM auth_lockouts WHERE lockout_key='ip:198.18.36.50'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let after = audits().await;
    listener.close().await.unwrap();
    forget(&db, ip, "").await;
    assert_eq!(decision.reason, "spray_detected");
    assert_eq!(note.expect("alert:spray").expect("open").payload(), ip);
    assert_eq!(armed, 1);
    assert_eq!(after, before + 1);
}

#[tokio::test]
async fn unanswered_rate_limit_and_captcha_counts_fail_closed() {
    let _s = SERIAL.lock().await;
    let dsn = dsn();
    let db = connect(&dsn).await;
    let (ip, user) = ("198.18.36.60", "gate367-rate@example.test");
    forget(&db, ip, user).await;
    let gate = load(
        pool(&dsn, 2, 1000, 300),
        WorkerPools::from_dsn(&dsn).unwrap(),
        with(with(quiet(), "rate_limit"), "captcha"),
    )
    .await;
    db.batch_execute("BEGIN; LOCK TABLE rate_limit_counters IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let rate = gate.decide(&meta(ip, user), true).await;
    db.batch_execute("ROLLBACK; BEGIN; LOCK TABLE auth_attempts IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let captcha = gate.decide(&meta(ip, user), false).await;
    db.batch_execute("ROLLBACK").await.unwrap();
    forget(&db, ip, user).await;
    assert_eq!(rate.reason, "rate_limit_unavailable");
    assert_eq!(captcha.reason, "captcha_unavailable");
}
