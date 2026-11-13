use guard_core::db::schema;

#[test]
fn test_apply_migrations_creates_tables() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db").to_string_lossy().to_string();
    let conn = rusqlite::Connection::open(&db_path).expect("open db");

    // Apply migrations
    schema::apply_migrations(&conn).expect("apply_migrations");

    // Verify totp_accounts table exists
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='totp_accounts'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "totp_accounts table should exist");

    // Verify vault_items table exists
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vault_items'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "vault_items table should exist");

    // Verify meta table exists
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "meta table should exist");

    // Verify totp_accounts has expected columns
    let mut stmt = conn.prepare("PRAGMA table_info(totp_accounts)").unwrap();
    let columns: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(columns.contains(&"id".to_string()));
    assert!(columns.contains(&"label".to_string()));
    assert!(columns.contains(&"issuer".to_string()));
    assert!(columns.contains(&"seed_enc".to_string()));
    assert!(columns.contains(&"uri_enc".to_string()));
    assert!(columns.contains(&"created_at".to_string()));
    assert!(columns.contains(&"sort_order".to_string()));
}
