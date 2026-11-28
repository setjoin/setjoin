//! Platform slice `terms-remaining`, group `monitor`: the dashboard's live counters
//! (`/admin/monitor/live`) and the mail-flow summary (`/admin/reports/summary`), Go's
//! `MonitorHandler` and `ReportsHandler`. Both are read-only via `AdminReadTx`.
use super::{done, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{SqlContract, StatementFailure};

async fn counts(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    contract: &'static SqlContract,
    width: usize,
) -> Vec<i64> {
    let zero = vec![0; width];
    let Ok(rows) = factory.run_admin_read_contract(admin, contract, &[]).await else {
        return zero;
    };
    let Some(row) = rows.first() else {
        return zero;
    };
    (0..width)
        .map(|i| row.try_get::<_, i64>(i).unwrap_or(0))
        .collect()
}

fn wants(sections: &str, name: &str) -> bool {
    sections.is_empty() || sections.contains(name)
}

pub async fn live(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    sections: &str,
    goroutines: u64,
) -> String {
    let mut out = String::from("{\"timestamp\":\"\"");
    if wants(sections, "dmarc") {
        let c = counts(factory, admin, &sql::MONITOR_DMARC_COUNTS, 4).await;
        let mut domains = Vec::new();
        if let Ok(rows) = factory
            .run_admin_read_contract(admin, &sql::MONITOR_DMARC_BY_DOMAIN, &[])
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
                let policy = match factory
                    .run_admin_read_contract(admin, &sql::MONITOR_DOMAIN_DMARC_POLICY, &[&domain])
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
        let c = counts(factory, admin, &sql::MONITOR_QUEUE_COUNTS, 3).await;
        out += &format!(
            ",\"queue\":{{\"pending\":{},\"deferred\":{},\"bounced\":{}}}",
            c[0], c[1], c[2]
        );
    }
    if wants(sections, "quarantine") {
        let active = counts(factory, admin, &sql::MONITOR_QUARANTINE_ACTIVE, 1).await;
        let today = counts(factory, admin, &sql::MONITOR_QUARANTINE_TODAY, 1).await;
        let released = counts(factory, admin, &sql::MONITOR_QUARANTINE_RELEASED, 1).await;
        out += &format!(
            ",\"quarantine\":{{\"active\":{},\"today\":{},\"released\":{}}}",
            active[0], today[0], released[0]
        );
    }
    if wants(sections, "volume") {
        let received = counts(factory, admin, &sql::MONITOR_VOLUME_RECEIVED, 1).await;
        let sent = counts(factory, admin, &sql::MONITOR_VOLUME_SENT, 1).await;
        let bytes = counts(factory, admin, &sql::MONITOR_VOLUME_BYTES, 1).await;
        out += &format!(
            ",\"volume\":{{\"received24h\":{},\"sent24h\":{},\"bytes24h\":{}}}",
            received[0], sent[0], bytes[0]
        );
    }
    if wants(sections, "threats") {
        let auth = counts(factory, admin, &sql::MONITOR_THREATS_AUTH, 1).await;
        let rbl = counts(factory, admin, &sql::MONITOR_THREATS_RBL, 1).await;
        let mut names = Vec::new();
        if let Ok(rows) = factory
            .run_admin_read_contract(admin, &sql::MONITOR_THREATS_VIRUS, &[])
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

pub fn days(raw: &str) -> i64 {
    let digits = !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit());
    match raw.parse::<i64>() {
        Ok(n) if digits && (1..=90).contains(&n) => n,
        _ => 7,
    }
}

async fn pairs(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    contract: &'static SqlContract,
    since: i64,
) -> Result<Vec<(String, i64)>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, contract, &[&since])
        .await?;
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

/// `GET /admin/reports/summary`.
pub async fn summary(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    period: &str,
    days: i64,
) -> Result<String, StatementFailure> {
    let totals = factory
        .run_admin_read_contract(admin, &sql::REPORTS_SUMMARY_TOTALS, &[&days])
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
    if let Ok(rows) = factory
        .run_admin_read_contract(admin, &sql::REPORTS_SUMMARY_DAILY, &[&days])
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
    let senders = pairs(factory, admin, &sql::REPORTS_TOP_SENDERS, days)
        .await
        .unwrap_or_default();
    let recipients = pairs(factory, admin, &sql::REPORTS_TOP_RECIPIENTS, days)
        .await
        .unwrap_or_default();
    let rules = pairs(factory, admin, &sql::REPORTS_RULE_TRIGGERS, days)
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
