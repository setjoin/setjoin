//! Review item 1: a stalled database bounds every executor call.
//!
//! - A server that accepts the TCP connection and never answers (a
//!   black hole) fails pool creation within `Timeouts::create`, and a full
//!   pool fails a lease within `Timeouts::pool_wait` — no database needed.
//! - A statement blocked on a lock (`LOCK TABLE … ACCESS EXCLUSIVE` held by
//!   another session) fails `read` and `read_scoped` within
//!   `Timeouts::statement` (server-side `statement_timeout` for the scoped
//!   read, client-side deadline plus cancel request for both). Needs the
//!   schema DSN (`TEST_DB_DSN`/`DB_DSN` owner, `DB_APP_DSN`); absent →
//!   `SETJOIN-PG-DB-SKIP`, `REQUIRE_DB=1` → FAIL.
use std::time::{Duration, Instant};

use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, Timeouts, Type};
use tokio::net::TcpListener;
use tokio_postgres::NoTls;

const FAST: Timeouts = Timeouts {
    pool_wait: Duration::from_millis(300),
    create: Duration::from_millis(300),
    statement: Duration::from_millis(400),
};

/// Accepts connections and holds them open without ever writing a byte.
async fn black_hole() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    addr
}

fn auth() -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(1).unwrap(),
        MailboxId::new(1).unwrap(),
        Generation(1),
    )
}

#[tokio::test]
async fn a_black_hole_database_fails_reads_within_the_create_bound() {
    let addr = black_hole().await;
    let dsn = format!(
        "host={} port={} user=x password=y dbname=z",
        addr.ip(),
        addr.port()
    );
    let exec = ScopedExecutor::from_dsn_with(&dsn, 1, FAST).unwrap();
    let t = Instant::now();
    assert!(exec.read("SELECT 1", &[]).await.is_err());
    assert!(exec.read_scoped(&auth(), "SELECT 1", &[]).await.is_err());
    let took = t.elapsed();
    assert!(took < Duration::from_secs(2), "took {took:?}");
}

#[tokio::test]
async fn the_default_bounds_are_finite() {
    let d = Timeouts::default();
    for b in [d.pool_wait, d.create, d.statement] {
        assert!(b > Duration::ZERO && b <= Duration::from_secs(5), "{b:?}");
    }
}

fn dsns(test: &str) -> Option<(String, String)> {
    let owner = ["TEST_DB_DSN", "DB_DSN"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
    let Some(owner) = owner else {
        if std::env::var("REQUIRE_DB").as_deref() == Ok("1") {
            panic!("REQUIRE_DB=1 but no TEST_DB_DSN/DB_DSN for {test}");
        }
        use std::io::Write;
        let line = format!("SETJOIN-PG-DB-SKIP (reason=no-dsn) test={test}\n");
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
        return None;
    };
    let app = std::env::var("DB_APP_DSN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| owner.clone());
    Some((owner, app))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_locked_table_fails_reads_within_the_statement_bound() {
    let Some((owner, app)) = dsns("a_locked_table_fails_reads_within_the_statement_bound") else {
        return;
    };
    let (mut locker, conn) = tokio_postgres::connect(&owner, NoTls).await.unwrap();
    tokio::spawn(conn);
    let tx = locker.transaction().await.unwrap();
    tx.batch_execute("LOCK TABLE feature_toggles IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();

    let exec = ScopedExecutor::from_dsn_with(&app, 2, FAST).unwrap();
    let sql = "SELECT count(*)::int8 FROM feature_toggles WHERE key = $1";
    let key = "feature.rust_mark_read".to_owned();
    let t = Instant::now();
    let plain = exec.read(sql, &[(&key, Type::TEXT)]).await;
    let plain_took = t.elapsed();
    let t = Instant::now();
    let scoped = exec.read_scoped(&auth(), sql, &[(&key, Type::TEXT)]).await;
    let scoped_took = t.elapsed();
    tx.rollback().await.unwrap();

    assert!(plain.is_err(), "{plain:?}");
    assert!(
        plain_took < Duration::from_secs(2),
        "read took {plain_took:?}"
    );
    let scoped = scoped.unwrap_err();
    assert!(
        scoped_took < Duration::from_secs(2),
        "read_scoped took {scoped_took:?}"
    );
    // The scoped read's own SET LOCAL statement_timeout cancelled it.
    assert_eq!(scoped.sqlstate.as_deref(), Some("57014"), "{scoped:?}");

    // The lock is gone: the same executor answers again (the stalled
    // connections were discarded, not pooled).
    let rows = exec.read(sql, &[(&key, Type::TEXT)]).await.unwrap();
    assert_eq!(rows.len(), 1);
}

/// A caller's own timeout (the gateway bounds its pre-checks) drops a read
/// mid-flight. The dropped read's connection may still be inside the scoped
/// `READ ONLY` transaction with the mailbox GUC set, so it must be
/// discarded, never handed to the next lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_dropped_mid_flight_never_returns_its_connection_to_the_pool() {
    let Some((owner, app)) =
        dsns("a_read_dropped_mid_flight_never_returns_its_connection_to_the_pool")
    else {
        return;
    };
    let (mut locker, conn) = tokio_postgres::connect(&owner, NoTls).await.unwrap();
    tokio::spawn(conn);
    let tx = locker.transaction().await.unwrap();
    tx.batch_execute("LOCK TABLE feature_toggles IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    // One connection: whatever the next read gets is the dropped read's
    // connection unless it was discarded.
    let exec = ScopedExecutor::from_dsn_with(&app, 1, Timeouts::default()).unwrap();
    let scope = auth();
    let blocked = exec.read_scoped(&scope, "SELECT count(*)::int8 FROM feature_toggles", &[]);
    assert!(tokio::time::timeout(Duration::from_millis(200), blocked)
        .await
        .is_err());
    tx.rollback().await.unwrap();

    let rows = exec
        .read(
            "SELECT current_setting('transaction_read_only') = 'off', \
                    coalesce(current_setting('app.current_mailbox_id', true), '')",
            &[],
        )
        .await
        .unwrap();
    let in_tx = !rows[0].get::<_, bool>(0);
    let guc: String = rows[0].get(1);
    assert!(!in_tx, "the next lease ran inside the dropped transaction");
    assert_eq!(guc, "", "the next lease inherited the dropped scope");
}
