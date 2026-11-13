//! Platform slice `terms-remaining`, group `monitor`: the dashboard's live counters
//! (`/admin/monitor/live`) and the mail-flow summary (`/admin/reports/summary`), Go's
//! `MonitorHandler` and `ReportsHandler`. Both are read-only.
//!
//! The live counters run on the worker credential (Go's `workerPool`: `messages` is under
//! row-level security and the counts are organization-wide). Go ignores every error of
//! the live queries, so a failed or missing query reads as zero, and a list with no rows
//! is `null`.
use super::{done, s};
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};

/// One `QueryRow(..).Scan(..)` whose error Go ignores: the zero values on failure.
async fn counts(exec: &ScopedExecutor, sql: &str, width: usize) -> Vec<i64> {
    let zero = vec![0; width];
    let Ok(rows) = exec.read(sql, &[]).await else {
        return zero;
    };
    let Some(row) = rows.first() else {
        return zero;
    };
    (0..width)
        .map(|i| row.try_get::<_, i64>(i).unwrap_or(0))
        .collect()
}

/// The sections of `?sections=`: empty means all, else a substring test as Go's.
fn wants(sections: &str, name: &str) -> bool {
    sections.is_empty() || sections.contains(name)
}

pub async fn live(worker: &ScopedExecutor, sections: &str, goroutines: u64) -> String {
    let mut out = String::from("{\"timestamp\":\"\"");
    if wants(sections, "dmarc") {
        let c = counts(
            worker,
            "SELECT COALESCE(SUM(count_pass),0)::bigint, COALESCE(SUM(count_fail),0)::bigint, \
             COALESCE(SUM(count_none),0)::bigint, COALESCE(SUM(count_temperror),0)::bigint \
             FROM dmarc_reports WHERE end_time = date_trunc('day', now() AT TIME ZONE 'UTC')",
            4,
        )
        .await;
        let mut domains = Vec::new();
        if let Ok(rows) = worker
            .read(
                "SELECT DISTINCT ON (domain) domain, COALESCE(SUM(count_pass),0)::bigint as pass, \
                 COALESCE(SUM(count_fail),0)::bigint as fail \
                 FROM dmarc_reports WHERE end_time = date_trunc('day', now() AT TIME ZONE 'UTC') \
                 GROUP BY domain ORDER BY domain LIMIT 20",
                &[],
            )
            .await
        {
            for row in &rows {
                let (Ok(domain), Ok(pass), Ok(fail)) = (
                    row.try_get::<_, String>(0),
                    row.try_get::<_, i64>(1),
                    row.try_get::<_, i64>(2),
                ) else {
                    continue;
                };
                let policy = match worker
                    .read(
                        "SELECT dmarc_policy FROM domains WHERE name = $1",
                        &[(&domain, Type::TEXT)],
                    )
                    .await
                {
                    Ok(found) => found
                        .first()
                        .and_then(|r| r.try_get::<_, String>(0).ok())
                        .unwrap_or_default(),
                    Err(_) => String::new(),
                };
                domains.push(format!(
                    "{{\"domain\":{},\"pass\":{pass},\"fail\":{fail},\"policy\":{}}}",
                    s(&domain),
                    s(&policy)
                ));
            }
        }
        let by_domain = if domains.is_empty() {
            "null".to_owned()
        } else {
            format!("[{}]", domains.join(","))
        };
        out += &format!(
            ",\"dmarc\":{{\"pass\":{},\"fail\":{},\"none\":{},\"temperror\":{},\"byDomain\":{by_domain}}}",
            c[0], c[1], c[2], c[3]
        );
    }
    if wants(sections, "queue") {
        let c = counts(
            worker,
            "SELECT COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0)::bigint, \
             COALESCE(SUM(CASE WHEN status='deferred' THEN 1 ELSE 0 END),0)::bigint, \
             COALESCE(SUM(CASE WHEN status='bounced' THEN 1 ELSE 0 END),0)::bigint \
             FROM outbound_queue",
            3,
        )
        .await;
        out += &format!(
            ",\"queue\":{{\"pending\":{},\"deferred\":{},\"bounced\":{}}}",
            c[0], c[1], c[2]
        );
    }
    if wants(sections, "quarantine") {
        let active = counts(
            worker,
            "SELECT COUNT(*) FROM quarantined_messages WHERE released_at IS NULL AND rejected_at IS NULL",
            1,
        )
        .await;
        let today = counts(
            worker,
            "SELECT COUNT(*) FROM quarantined_messages \
             WHERE quarantined_at >= date_trunc('day', now() AT TIME ZONE 'UTC')",
            1,
        )
        .await;
        let released = counts(
            worker,
            "SELECT COUNT(*) FROM quarantined_messages WHERE released_at IS NOT NULL",
            1,
        )
        .await;
        out += &format!(
            ",\"quarantine\":{{\"active\":{},\"today\":{},\"released\":{}}}",
            active[0], today[0], released[0]
        );
    }
    if wants(sections, "volume") {
        let received = counts(
            worker,
            "SELECT COUNT(*) FROM messages WHERE received_at >= now() - interval '24 hours'",
            1,
        )
        .await;
        let sent = counts(
            worker,
            "SELECT COUNT(*) FROM outbound_queue WHERE queued_at >= now() - interval '24 hours'",
            1,
        )
        .await;
        let bytes = counts(
            worker,
            "SELECT COALESCE(SUM(size_bytes),0)::bigint FROM messages WHERE received_at >= now() - interval '24 hours'",
            1,
        )
        .await;
        out += &format!(
            ",\"volume\":{{\"received24h\":{},\"sent24h\":{},\"bytes24h\":{}}}",
            received[0], sent[0], bytes[0]
        );
    }
    if wants(sections, "threats") {
        let auth = counts(
            worker,
            "SELECT COUNT(*) FROM message_trace WHERE event = 'auth_failure' \
             AND traced_at >= now() - interval '24 hours'",
            1,
        )
        .await;
        let rbl = counts(
            worker,
            "SELECT COUNT(*) FROM message_trace WHERE event = 'rbl_block' \
             AND traced_at >= now() - interval '24 hours'",
            1,
        )
        .await;
        let mut names = Vec::new();
        if let Ok(rows) = worker
            .read(
                "SELECT virus_name, COUNT(*)::bigint as cnt FROM quarantined_messages \
                 WHERE virus_name IS NOT NULL AND quarantined_at >= now() - interval '7 days' \
                 GROUP BY virus_name ORDER BY cnt DESC LIMIT 5",
                &[],
            )
            .await
        {
            for row in &rows {
                if let (Ok(name), Ok(count)) =
                    (row.try_get::<_, String>(0), row.try_get::<_, i64>(1))
                {
                    names.push(format!("{{\"name\":{},\"count\":{count}}}", s(&name)));
                }
            }
        }
        let top = if names.is_empty() {
            "null".to_owned()
        } else {
            format!("[{}]", names.join(","))
        };
        out += &format!(
            ",\"threats\":{{\"authFailures\":{},\"rblBlocks\":{},\"topVirusNames\":{top}}}",
            auth[0], rbl[0]
        );
    }
    if wants(sections, "system") {
        out += &format!(",\"system\":{{\"goroutines\":{goroutines}}}");
    }
    out.push('}');
    done(out)
}

/// Go's `parseInt` as `Summary` uses it: `Some(n)` only for an all-digit number that
/// `json.Number.Int64` accepts, then `0 < n <= 90`; anything else keeps 7 days.
pub fn days(raw: &str) -> i64 {
    let digits = !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit());
    match raw.parse::<i64>() {
        Ok(n) if digits && (1..=90).contains(&n) => n,
        _ => 7,
    }
}

async fn pairs(
    exec: &ScopedExecutor,
    sql: &str,
    since: i64,
) -> Result<Vec<(String, i64)>, StatementFailure> {
    let rows = exec.read(sql, &[(&since, Type::INT8)]).await?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some((
                r.try_get::<_, String>(0).ok()?,
                r.try_get::<_, i64>(1).ok()?,
            ))
        })
        .collect())
}

/// `GET /admin/reports/summary`. `period` is the raw `?days=` text (`7` when absent). The
/// first query's failure is the only one Go answers with an error.
pub async fn summary(
    exec: &ScopedExecutor,
    period: &str,
    days: i64,
) -> Result<String, StatementFailure> {
    let since = "(now() - ($1::bigint * 86400) * interval '1 second')";
    let totals = exec
        .read(
            &format!(
                "SELECT COALESCE(COUNT(*) FILTER (WHERE event IN ('delivered','deferred')), 0)::bigint, \
                 COALESCE(COUNT(*) FILTER (WHERE event = 'received'), 0)::bigint, \
                 COALESCE(COUNT(*) FILTER (WHERE event = 'bounced'), 0)::bigint, \
                 COALESCE(COUNT(*) FILTER (WHERE event = 'spam_filtered'), 0)::bigint \
                 FROM message_trace WHERE occurred_at >= {since}"
            ),
            &[(&days, Type::INT8)],
        )
        .await?;
    let row = totals.first().ok_or_else(super::invalid)?;
    let bad = |_| super::invalid();
    let (sent, received, bounced, spam): (i64, i64, i64, i64) = (
        row.try_get(0).map_err(bad)?,
        row.try_get(1).map_err(bad)?,
        row.try_get(2).map_err(bad)?,
        row.try_get(3).map_err(bad)?,
    );
    let mut daily = Vec::new();
    if let Ok(rows) = exec
        .read(
            &format!(
                "SELECT day::text, sent, received, bounced, spam FROM (\
                 SELECT date_trunc('day', occurred_at)::date as day, \
                 COALESCE(COUNT(*) FILTER (WHERE event IN ('delivered','deferred')), 0)::bigint as sent, \
                 COALESCE(COUNT(*) FILTER (WHERE event = 'received'), 0)::bigint as received, \
                 COALESCE(COUNT(*) FILTER (WHERE event = 'bounced'), 0)::bigint as bounced, \
                 COALESCE(COUNT(*) FILTER (WHERE event = 'spam_filtered'), 0)::bigint as spam \
                 FROM message_trace WHERE occurred_at >= {since} GROUP BY day ORDER BY day) q ORDER BY day"
            ),
            &[(&days, Type::INT8)],
        )
        .await
    {
        for r in &rows {
            if let (Ok(day), Ok(a), Ok(b), Ok(c), Ok(d)) = (
                r.try_get::<_, String>(0),
                r.try_get::<_, i64>(1),
                r.try_get::<_, i64>(2),
                r.try_get::<_, i64>(3),
                r.try_get::<_, i64>(4),
            ) {
                daily.push(format!(
                    "{{\"date\":{},\"sent\":{a},\"received\":{b},\"bounced\":{c},\"spam\":{d}}}",
                    s(&day)
                ));
            }
        }
    }
    let actors = |list: Vec<(String, i64)>, key: &str| -> String {
        list.iter()
            .map(|(name, n)| format!("{{\"{key}\":{},\"count\":{n}}}", s(name)))
            .collect::<Vec<_>>()
            .join(",")
    };
    let senders = pairs(
        exec,
        &format!(
            "SELECT from_addr, COUNT(*)::bigint as cnt FROM message_trace \
             WHERE occurred_at >= {since} AND event IN ('received','delivered','deferred') \
             GROUP BY from_addr ORDER BY cnt DESC LIMIT 10"
        ),
        days,
    )
    .await
    .unwrap_or_default();
    let recipients = pairs(
        exec,
        &format!(
            "SELECT rcpt_addr, COUNT(*)::bigint as cnt FROM message_trace \
             WHERE occurred_at >= {since} AND event IN ('received','delivered','deferred') \
             GROUP BY rcpt_addr ORDER BY cnt DESC LIMIT 10"
        ),
        days,
    )
    .await
    .unwrap_or_default();
    let rules = pairs(
        exec,
        &format!(
            "SELECT COALESCE(details->>'rule_name','unknown') as rule_name, COUNT(*)::bigint as cnt \
             FROM message_trace WHERE occurred_at >= {since} AND event = 'rule_applied' \
             GROUP BY rule_name ORDER BY cnt DESC LIMIT 10"
        ),
        days,
    )
    .await
    .unwrap_or_default();
    Ok(done(format!(
        "{{\"period\":{},\"totalSent\":{sent},\"totalReceived\":{received},\"totalBounced\":{bounced},\"spamCount\":{spam},\"daily\":[{}],\"topSenders\":[{}],\"topRecipients\":[{}],\"ruleTriggers\":[{}]}}",
        s(period),
        daily.join(","),
        actors(senders, "email"),
        actors(recipients, "email"),
        actors(rules, "ruleName"),
    )))
}
