//! Slice `dmarc` (#324): Go's `admin.DMARCHandler` (`Live`, `RecentFailures`, `Trend`) and
//! `admin.AuthLogHandler.List`. All four are admin reads behind the console gate the adapter
//! checks (`requireMailPerm` for DMARC, `requireLogsPerm` for the auth log). Go ignores most
//! scan and query errors (a failed read counts zero), which is mirrored below.
use super::{done, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{Row, StatementFailure};

fn sums(rows: &[Row]) -> [i64; 4] {
    let mut out = [0; 4];
    if let Some(row) = rows.first() {
        for (i, slot) in out.iter_mut().enumerate() {
            // Go ignores the Scan error: a failed column leaves the zero value.
            *slot = row.try_get::<_, i64>(i).unwrap_or(0);
        }
    }
    out
}

/// Go's `DMARCLive` JSON; `by_domain` `None` renders `null` (nil slice).
fn live_json(totals: [i64; 4], by_domain: Option<Vec<String>>) -> String {
    done(format!(
        "{{\"pass\":{},\"fail\":{},\"none\":{},\"temperror\":{},\"byDomain\":{}}}",
        totals[0],
        totals[1],
        totals[2],
        totals[3],
        by_domain.map_or("null".to_owned(), |d| format!("[{}]", d.join(",")))
    ))
}

/// `GET /admin/dmarc/live`; a scoped admin's domain that cannot be resolved is Go's empty answer.
pub async fn live(factory: &TxFactory, admin: &AdminPermissionProof) -> String {
    let domain_scope = admin.enforced_domain_scope().unwrap_or(0);
    let mut name = String::new();
    if domain_scope > 0 {
        let found = match factory
            .run_admin_read_contract(admin, &sql::DMARC_DOMAIN_NAME, &[&domain_scope])
            .await
        {
            Ok(rows) => rows.first().and_then(|r| r.try_get::<_, String>(0).ok()),
            Err(_) => None,
        };
        let Some(found) = found else {
            return live_json([0; 4], None);
        };
        name = found;
    }
    let totals = match factory
        .run_admin_read_contract(admin, &sql::DMARC_LIVE_TOTALS, &[&name])
        .await
    {
        Ok(rows) => sums(&rows),
        Err(_) => [0; 4],
    };
    // One statement for the per-domain rows and each row's policy (Go asks per row; a
    // domain with no `domains` row keeps the empty policy).
    let rows = match factory.begin_admin_read(admin).await {
        Ok(mut tx) => {
            let res = tx
                .query_iterated_contract(&sql::DMARC_LIVE_BY_DOMAIN, &[&name])
                .await;
            let _ = tx.finish().await;
            res
        }
        Err(e) => Err(e),
    };
    // Go ignores the query error (`rows, _ :=`): no rows is a nil slice.
    let by_domain = rows.ok().and_then(|rows| {
        let items: Vec<String> = rows
            .iter()
            .filter_map(|r| {
                Some(format!(
                    "{{\"domain\":{},\"pass\":{},\"fail\":{},\"policy\":{}}}",
                    s(&r.try_get::<_, String>(0).ok()?),
                    r.try_get::<_, i64>(1).ok()?,
                    r.try_get::<_, i64>(2).ok()?,
                    s(&r.try_get::<_, String>(3).ok()?),
                ))
            })
            .collect();
        (!items.is_empty()).then_some(items)
    });
    live_json(totals, by_domain)
}

/// `GET /admin/dmarc/failures`: `limit` is already Go's `ParseLimitOffset(100, 200)`.
/// A query, scan or iteration error is Go's 500.
pub async fn failures(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    limit: i64,
) -> Result<String, StatementFailure> {
    let domain_scope = admin.enforced_domain_scope().unwrap_or(0);
    let rows = factory
        .run_admin_read_contract(admin, &sql::DMARC_FAILURES, &[&limit, &domain_scope])
        .await?;
    let mut items = vec![];
    for row in &rows {
        let text = |i: usize| row.try_get::<_, String>(i).map_err(|_| invalid());
        items.push(format!(
            "{{\"time\":{},\"from\":{},\"spf\":{},\"dkim\":{},\"dmarc\":{},\"details\":{}}}",
            s(&text(0)?),
            s(&text(1)?),
            s(&text(3)?),
            s(&text(4)?),
            s(&text(5)?),
            s(&text(2)?)
        ));
    }
    Ok(done(if items.is_empty() {
        "{\"failures\":null}".to_owned()
    } else {
        format!("{{\"failures\":[{}]}}", items.join(","))
    }))
}

/// `GET /admin/dmarc/trend`: a query error is Go's 500; a scoped admin whose domain is
/// gone gets `{"days":[]}`; an empty result is `{"days":null}`.
pub async fn trend(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let domain_scope = admin.enforced_domain_scope().unwrap_or(0);
    let mut name = String::new();
    if domain_scope > 0 {
        let found = match factory
            .run_admin_read_contract(admin, &sql::DMARC_DOMAIN_NAME, &[&domain_scope])
            .await
        {
            Ok(rows) => rows.first().and_then(|r| r.try_get::<_, String>(0).ok()),
            Err(_) => None,
        };
        let Some(found) = found else {
            return Ok(done("{\"days\":[]}".into()));
        };
        name = found;
    }
    let mut tx = factory.begin_admin_read(admin).await?;
    let rows = tx
        .query_iterated_contract(&sql::DMARC_TREND, &[&name])
        .await?;
    tx.finish().await?;
    let days: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            Some(format!(
                "{{\"date\":{},\"pass\":{},\"fail\":{},\"none\":{}}}",
                s(&r.try_get::<_, String>(0).ok()?),
                r.try_get::<_, i64>(1).ok()?,
                r.try_get::<_, i64>(2).ok()?,
                r.try_get::<_, i64>(3).ok()?,
            ))
        })
        .collect();
    Ok(done(if days.is_empty() {
        "{\"days\":null}".to_owned()
    } else {
        format!("{{\"days\":[{}]}}", days.join(","))
    }))
}

/// `GET /admin/auth-log`: filters bind as in Go; `limit` is the raw text (Go binds the
/// string, so a non-integer or negative value is a database error that Go ignores). The first row
/// with a NULL email fails Go's `Scan` into a string, which ends the iteration.
pub async fn auth_log(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    provider: &str,
    event: &str,
    since: &str,
    email: &str,
    limit: &str,
) -> Result<String, StatementFailure> {
    let provider_arg = if provider == "all" { "" } else { provider };
    let event_arg = if event == "all" { "" } else { event };
    let limit_arg = if limit.is_empty() { "200" } else { limit };
    // pgx reports a Bind-time error (a bad interval or LIMIT text) through `Rows.Err`, which
    // Go never checks: the handler answers an empty list. Only a failure with no server
    // verdict (pool, timeout) is Go's `Query` error.
    let mut tx = factory.begin_admin_read(admin).await?;
    let rows = match tx
        .query_iterated_contract(
            &sql::DMARC_AUTH_LOG,
            &[&provider_arg, &event_arg, &since, &email, &limit_arg],
        )
        .await
    {
        Ok(rows) => {
            let _ = tx.finish().await;
            rows
        }
        Err(failure) if failure.sqlstate.is_some() => {
            let _ = tx.finish().await;
            vec![]
        }
        Err(failure) => {
            let _ = tx.finish().await;
            return Err(failure);
        }
    };
    // A failed `Scan` (NULL email) makes pgx close the rows: Go keeps what it had and stops.
    let items: Vec<String> = rows
        .iter()
        .map_while(|r| {
            let user: Option<i64> = r.try_get(1).ok()?;
            Some(format!(
                "{{\"id\":{}{},\"email\":{},\"event\":{},\"provider\":{},\"ipAddress\":{},\"occurredAt\":{}}}",
                r.try_get::<_, i64>(0).ok()?,
                user.map_or(String::new(), |u| format!(",\"userId\":{u}")),
                s(&r.try_get::<_, String>(2).ok()?),
                s(&r.try_get::<_, String>(3).ok()?),
                s(&r.try_get::<_, String>(4).ok()?),
                s(&r.try_get::<_, String>(5).ok()?),
                s(&r.try_get::<_, String>(6).ok()?),
            ))
        })
        .collect();
    Ok(done(format!("[{}]", items.join(","))))
}
