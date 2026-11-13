//! Slice `dmarc` (#324): Go's `admin.DMARCHandler` (`Live`, `RecentFailures`, `Trend`) and
//! `admin.AuthLogHandler.List`. All four are reads behind the admin console gate the adapter
//! checks (`requireMailPerm` for DMARC, `requireLogsPerm` for the auth log). Go ignores most
//! scan and query errors (a failed read counts zero), which is mirrored below.
use super::{done, invalid, nano, s};
use setjoin_pg::{Param, Row, ScopedExecutor, StatementFailure, Type};

const TODAY: &str = "end_time = date_trunc('day', now() AT TIME ZONE 'UTC')";

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
pub async fn live(worker: &ScopedExecutor, domain_scope: i64) -> String {
    let mut filter = String::new();
    let mut name = String::new();
    if domain_scope > 0 {
        let found = match worker
            .read(
                "SELECT name FROM domains WHERE id = $1",
                &[(&domain_scope, Type::INT8)],
            )
            .await
        {
            Ok(rows) => rows.first().and_then(|r| r.try_get::<_, String>(0).ok()),
            Err(_) => None,
        };
        let Some(found) = found else {
            return live_json([0; 4], None);
        };
        name = found;
        filter = "domain = $1 AND ".into();
    }
    let params: &[Param<'_>] = if domain_scope > 0 {
        &[(&name, Type::TEXT)]
    } else {
        &[]
    };
    let totals = match worker
        .read(
            &format!(
                "SELECT COALESCE(SUM(count_pass),0)::bigint, COALESCE(SUM(count_fail),0)::bigint, \
                 COALESCE(SUM(count_none),0)::bigint, COALESCE(SUM(count_temperror),0)::bigint \
                 FROM dmarc_reports WHERE {filter}{TODAY}"
            ),
            params,
        )
        .await
    {
        Ok(rows) => sums(&rows),
        Err(_) => [0; 4],
    };
    // One statement for the per-domain rows and each row's policy (Go asks per row; a
    // domain with no `domains` row keeps the empty policy).
    let rows = worker
        .read_iterated(
            &format!(
                "SELECT q.domain, q.pass, q.fail, COALESCE((SELECT d.dmarc_policy FROM domains d WHERE d.name = q.domain LIMIT 1), '') \
                 FROM (SELECT DISTINCT ON (domain) domain, \
                 COALESCE(SUM(count_pass),0)::bigint as pass, COALESCE(SUM(count_fail),0)::bigint as fail \
                 FROM dmarc_reports WHERE {filter}{TODAY} \
                 GROUP BY domain ORDER BY domain LIMIT 20) q ORDER BY q.domain"
            ),
            params,
        )
        .await;
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
    worker: &ScopedExecutor,
    domain_scope: i64,
    limit: i64,
) -> Result<String, StatementFailure> {
    let scope = if domain_scope > 0 {
        " AND mb.domain_id = $2"
    } else {
        ""
    };
    let sql = format!(
        "SELECT to_char(m.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), m.from_addr, ''::text, \
         COALESCE(m.spf_result,''), COALESCE(m.dkim_result,''), m.dmarc_result \
         FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id \
         WHERE m.received_at >= now() - interval '24 hours' AND m.dmarc_result = 'fail'{scope} \
         ORDER BY m.received_at DESC LIMIT $1"
    );
    let rows = if domain_scope > 0 {
        worker
            .read(&sql, &[(&limit, Type::INT8), (&domain_scope, Type::INT8)])
            .await?
    } else {
        worker.read(&sql, &[(&limit, Type::INT8)]).await?
    };
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
pub async fn trend(worker: &ScopedExecutor, domain_scope: i64) -> Result<String, StatementFailure> {
    let mut name = String::new();
    let mut filter = "";
    if domain_scope > 0 {
        let found = match worker
            .read(
                "SELECT name FROM domains WHERE id = $1",
                &[(&domain_scope, Type::INT8)],
            )
            .await
        {
            Ok(rows) => rows.first().and_then(|r| r.try_get::<_, String>(0).ok()),
            Err(_) => None,
        };
        let Some(found) = found else {
            return Ok(done("{\"days\":[]}".into()));
        };
        name = found;
        filter = "domain = $1 AND ";
    }
    let params: &[Param<'_>] = if domain_scope > 0 {
        &[(&name, Type::TEXT)]
    } else {
        &[]
    };
    let rows = worker
        .read_iterated(
            &format!(
                "SELECT to_char(t.day,'YYYY-MM-DD'), t.pass, t.fail, t.nonec FROM \
                 (SELECT begin_time::DATE as day, COALESCE(SUM(count_pass),0)::bigint AS pass, \
                 COALESCE(SUM(count_fail),0)::bigint AS fail, COALESCE(SUM(count_none),0)::bigint AS nonec \
                 FROM dmarc_reports WHERE {filter}begin_time >= now() - interval '30 days' \
                 GROUP BY day ORDER BY day) t ORDER BY t.day"
            ),
            params,
        )
        .await?;
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
    exec: &ScopedExecutor,
    provider: &str,
    event: &str,
    since: &str,
    email: &str,
    limit: &str,
) -> Result<String, StatementFailure> {
    let mut sql = format!(
        "SELECT id, user_id, email, event, provider, COALESCE(host(ip_address::inet), ''), {} \
         FROM auth_event_log WHERE 1=1",
        nano("occurred_at")
    );
    let mut args: Vec<&str> = vec![];
    if !provider.is_empty() && provider != "all" {
        args.push(provider);
        sql += &format!(" AND provider = ${}", args.len());
    }
    if !event.is_empty() && event != "all" {
        args.push(event);
        sql += &format!(" AND event = ${}", args.len());
    }
    if !since.is_empty() {
        args.push(since);
        sql += &format!(" AND occurred_at > now() - ${}::text::interval", args.len());
    }
    if !email.is_empty() {
        args.push(email);
        sql += &format!(" AND email ILIKE '%' || ${} || '%'", args.len());
    }
    args.push(if limit.is_empty() { "200" } else { limit });
    sql += &format!(
        " ORDER BY occurred_at DESC LIMIT ${}::text::bigint",
        args.len()
    );
    let params: Vec<Param<'_>> = args.iter().map(|a| (a as _, Type::TEXT)).collect();
    // pgx reports a Bind-time error (a bad interval or LIMIT text) through `Rows.Err`, which
    // Go never checks: the handler answers an empty list. Only a failure with no server
    // verdict (pool, timeout) is Go's `Query` error.
    let rows = match exec.read_iterated(&sql, &params).await {
        Ok(rows) => rows,
        Err(failure) if failure.sqlstate.is_some() => vec![],
        Err(failure) => return Err(failure),
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
