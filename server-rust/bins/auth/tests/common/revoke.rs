//! Request-role privilege faults for the #454 fail-closed tests. A fault is always undone:
//! `restore` undoes it through the test's owner connection (a Result for its cleanup), and the
//! guard repeats the idempotent undo on drop from its own thread, runtime and owner connection,
//! so a panic between fault and restore cannot leave the database revoked.
#![allow(dead_code)]
pub type Err = Box<dyn std::error::Error + Send + Sync>;

pub struct Revoked {
    owner: String,
    undo: String,
}

impl Revoked {
    pub async fn restore(&self, c: &tokio_postgres::Client) -> Result<(), Err> {
        c.batch_execute(&self.undo).await?;
        Ok(())
    }
}

impl Drop for Revoked {
    fn drop(&mut self) {
        let (owner, undo) = (self.owner.clone(), self.undo.clone());
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                eprintln!("FAILCLOSED-REVOKE: no runtime to undo `{undo}`");
                return;
            };
            rt.block_on(async move {
                // Bounded (S1): a hung owner connection must never hang or panic inside drop.
                let limit = std::time::Duration::from_secs(10);
                let connected = tokio::time::timeout(
                    limit,
                    tokio_postgres::connect(&owner, tokio_postgres::NoTls),
                )
                .await;
                let Ok(Ok((client, connection))) = connected else {
                    eprintln!("FAILCLOSED-REVOKE: could not reconnect to undo `{undo}`");
                    return;
                };
                let task = tokio::spawn(connection);
                match tokio::time::timeout(limit, client.batch_execute(&undo)).await {
                    Ok(Ok(())) => {}
                    _ => eprintln!("FAILCLOSED-REVOKE: undo failed or timed out: `{undo}`"),
                }
                drop(client);
                let _ = tokio::time::timeout(limit, task).await;
            });
        })
        .join();
    }
}

/// Run `fault` as the owner and prove `probe` now fails for the request role with
/// insufficient_privilege. Preconditions make `undo` an exact restore: setjoin_app holds a
/// direct, non-grantable table-level SELECT on `table`, no column-level grant there, and the
/// probe succeeds before the fault. The guard exists before `fault` runs.
pub async fn revoke(
    owner_dsn: &str,
    c: &tokio_postgres::Client,
    app: &setjoin_pg::ScopedExecutor,
    table: &str,
    fault: &str,
    undo: &str,
    probe: &str,
) -> Result<Revoked, Err> {
    let direct: Vec<bool> = c
        .query(
            "SELECT x.is_grantable FROM pg_class k CROSS JOIN LATERAL aclexplode(k.relacl) x WHERE k.oid=to_regclass($1) AND x.grantee=to_regrole('setjoin_app') AND x.privilege_type='SELECT'",
            &[&table],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    if direct != [false] {
        return Err(format!("STOP: setjoin_app has no single direct, non-grantable SELECT on {table} ({direct:?}); the fault could not be undone exactly").into());
    }
    let columns: bool = c
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE a.attrelid=to_regclass($1) AND a.attacl IS NOT NULL AND x.grantee=to_regrole('setjoin_app'))",
            &[&table],
        )
        .await?
        .get(0);
    if columns {
        return Err(format!("STOP: setjoin_app already holds column-level grants on {table}; the fault could not be undone exactly").into());
    }
    if let Err(f) = app.read(probe, &[]).await {
        return Err(format!("precondition: `{probe}` fails before the fault: {f:?}").into());
    }
    let guard = Revoked {
        owner: owner_dsn.to_owned(),
        undo: undo.to_owned(),
    };
    c.batch_execute(fault).await?;
    match app.read(probe, &[]).await {
        Err(f) if f.sqlstate.as_deref() == Some("42501") => Ok(guard),
        Err(f) => Err(format!("precondition: `{probe}` failed after `{fault}` with {f:?}, not insufficient_privilege (42501)").into()),
        Ok(_) => Err(format!("precondition: `{probe}` still succeeds for setjoin_app after `{fault}`").into()),
    }
}

/// Revoke SELECT on one table from the request role; the undo re-grants exactly that SELECT.
pub async fn table(
    owner_dsn: &str,
    c: &tokio_postgres::Client,
    app: &setjoin_pg::ScopedExecutor,
    table: &str,
) -> Result<Revoked, Err> {
    revoke(
        owner_dsn,
        c,
        app,
        table,
        &format!("REVOKE SELECT ON {table} FROM setjoin_app"),
        &format!("GRANT SELECT ON {table} TO setjoin_app"),
        &format!("SELECT 1 FROM {table} LIMIT 1"),
    )
    .await
}
