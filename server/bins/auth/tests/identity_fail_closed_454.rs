//! #454 fail-closed identity DB lookup tests (relocated out of
//! `crates/domains/identity/` in Wave 1.8d so domain crates never construct
//! `ScopedExecutor::from_dsn`).

#[tokio::test]
async fn risk_lookup_error_is_an_error() {
    let exec = setjoin_pg::ScopedExecutor::from_dsn("postgres://nobody@127.0.0.1:1/none", 1)
        .expect("unreachable pool");
    let db = setjoin_pg::AuthDb::from_executors(exec.clone(), exec);
    assert!(setjoin_identity::login::risk_for_user(&db, 7)
        .await
        .is_err());
}

#[tokio::test]
async fn webauthn_factor_query_error_is_an_error() {
    let exec = setjoin_pg::ScopedExecutor::from_dsn("postgres://nobody@127.0.0.1:1/none", 1)
        .expect("unreachable pool");
    let db = setjoin_pg::AuthDb::from_executors(exec.clone(), exec);
    assert!(setjoin_identity::webauthn::factors_for_user(&db, 7)
        .await
        .is_err());
}

#[tokio::test]
async fn webauthn_absent_user_row_is_an_error() {
    let Some(dsn) = std::env::var("TEST_DB_DSN").ok().filter(|v| !v.is_empty()) else {
        assert!(
            std::env::var("REQUIRE_DB").unwrap_or_default().is_empty(),
            "TEST_DB_DSN (REQUIRE_DB lane)"
        );
        eprintln!("IDENTITY-DB-SKIP (reason=no-dsn) test=webauthn_absent_user_row_is_an_error");
        return;
    };
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&dsn, 1).expect("test pool");
    let db = setjoin_pg::AuthDb::from_executors(exec.clone(), exec);
    assert!(setjoin_identity::webauthn::factors_for_user(&db, i64::MAX)
        .await
        .is_err());
}
