//! `dmarc-report` (#324): frozen Go's `smtp.DMARCReportWorker`. Five minutes after start and
//! then every 24 hours it builds one RFC 7489 aggregate report per `(report_uri, domain)`
//! older than an hour, queues it as an inline-raw outbound email and deletes that domain's
//! rows. Writes are the same single statements Go issues (one INSERT into `outbound_queue`,
//! one DELETE of `dmarc_reports`) on the worker credential, and a failed step logs and
//! moves on to the next domain, as Go does. Start it with `RUST_WORKERS_ON=dmarc-report`
//! only together with `GO_WORKERS_OFF=dmarc-report`, and only while `feature.dmarc_reporting`
//! is on (Go reads the toggle once at start; absent row means on, the registry default).
//!
//! Parity quirks kept on purpose: the attachment is declared `application/gzip` and
//! `base64` but carries the raw XML; `policy_domain` is read with `LIMIT 1` and no ORDER BY;
//! the record always claims `source_ip` 0.0.0.0 and the evaluation `fail` when any row
//! failed; the `Date:` header is rendered in UTC (Go renders its local zone, UTC in the
//! image).
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use std::{future::Future, time::Duration};

pub const NAME: &str = "dmarc-report";
pub const INITIAL_DELAY: Duration = Duration::from_secs(300);
pub const INTERVAL: Duration = Duration::from_secs(24 * 3600);

pub struct DmarcReport {
    db: WorkerDatabase,
    hostname: String,
}

fn warn(what: &str, error: impl std::fmt::Display) {
    eprintln!("dmarc report worker: {what}: {error}");
}

/// `parseRUA`: the first `mailto:` URI of a comma list, size limit (`!10m`) stripped.
pub fn parse_rua(rua: &str) -> String {
    for uri in rua.split(',') {
        let uri = uri.trim();
        if let Some(email) = uri.strip_prefix("mailto:") {
            return email.split('!').next().unwrap_or("").to_owned();
        }
    }
    String::new()
}

/// `encoding/xml`'s `EscapeText`.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c if matches!(c, '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}') => {
                out.push(c)
            }
            _ => out.push('\u{FFFD}'),
        }
    }
    out
}

/// The aggregate report as `xml.MarshalIndent(report, "", "  ")` under `xml.Header`.
#[allow(clippy::too_many_arguments)]
pub fn aggregate_xml(
    org: &str,
    hostname: &str,
    domain: &str,
    now_unix: i64,
    begin: i64,
    end: i64,
    total: i64,
    failed: bool,
) -> String {
    let eval = if failed { "fail" } else { "pass" };
    let org = escape(org);
    let lines: Vec<(usize, String)> = vec![
        (0, "<feedback>".into()),
        (1, "<version>1</version>".into()),
        (1, "<report_metadata>".into()),
        (2, format!("<org_name>{org}</org_name>")),
        (
            2,
            format!(
                "<email>{}</email>",
                escape(&format!("dmarc-reports@{hostname}"))
            ),
        ),
        (
            2,
            format!(
                "<report_id>{}</report_id>",
                escape(&format!("{domain}.{now_unix}"))
            ),
        ),
        (2, "<date_range>".into()),
        (3, format!("<begin>{begin}</begin>")),
        (3, format!("<end>{end}</end>")),
        (2, "</date_range>".into()),
        (1, "</report_metadata>".into()),
        (1, "<policy_published>".into()),
        (2, format!("<domain>{org}</domain>")),
        (2, "<adkim>r</adkim>".into()),
        (2, "<aspf>r</aspf>".into()),
        (2, "<p>none</p>".into()),
        (2, "<pct>100</pct>".into()),
        (1, "</policy_published>".into()),
        (1, "<record>".into()),
        (2, "<source_ip>0.0.0.0</source_ip>".into()),
        (2, format!("<count>{total}</count>")),
        (2, "<policy_evaluated>".into()),
        (3, "<disposition>none</disposition>".into()),
        (3, format!("<dkim>{eval}</dkim>")),
        (3, format!("<spf>{eval}</spf>")),
        (2, "</policy_evaluated>".into()),
        (2, "<auth_results>".into()),
        (3, "<dkim>".into()),
        (4, format!("<domain>{org}</domain>")),
        (4, format!("<result>{eval}</result>")),
        (3, "</dkim>".into()),
        (3, "<spf>".into()),
        (4, format!("<domain>{org}</domain>")),
        (4, format!("<result>{eval}</result>")),
        (3, "</spf>".into()),
        (2, "</auth_results>".into()),
    ];
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    for (depth, line) in lines {
        out.push_str(&"  ".repeat(depth));
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str("  </record>\n</feedback>");
    out
}

/// The RFC 5322 message Go queues inline.
pub fn raw_message(
    hostname: &str,
    to: &str,
    domain: &str,
    message_id: &str,
    xml: &str,
    date: &str,
    boundary: &str,
) -> String {
    format!(
        "From: DMARC Reporter <dmarc-reports@{hostname}>\r\n\
To: {to}\r\n\
Subject: Report Domain: {domain} Submitter: {hostname}\r\n\
Date: {date}\r\n\
Message-ID: {message_id}\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary={boundary}\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\n\
This is a DMARC aggregate report for {domain}.\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: application/gzip\r\n\
Content-Disposition: attachment; filename=dmarc.xml\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
{xml}\r\n--{boundary}--\r\n"
    )
}

impl DmarcReport {
    pub fn new(db: WorkerDatabase, hostname: String) -> Self {
        Self { db, hostname }
    }

    /// Go's `Run`: first report after five minutes, then 24 hours after each finished pass.
    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        tokio::pin!(stop);
        let mut delay = INITIAL_DELAY;
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = tokio::time::sleep(delay) => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
            delay = INTERVAL;
        }
    }

    /// One `sendReports` pass. Public: the oracle drives exactly one tick.
    pub async fn tick(&self) {
        let c = match self.db.connect_session().await {
            Ok(c) => c,
            Err(e) => return warn("connect failed", e),
        };
        let rows = match c
            .query(
                "SELECT DISTINCT ON (report_uri, domain) report_uri, domain FROM dmarc_reports \
                 WHERE created_at < now() - interval '1 hour' ORDER BY report_uri, domain",
                &[],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => return warn("query failed", e),
        };
        for row in rows {
            let (Ok(uri), Ok(domain)) = (row.try_get::<_, String>(0), row.try_get::<_, String>(1))
            else {
                continue;
            };
            let email = parse_rua(&uri);
            if email.is_empty() {
                eprintln!("dmarc report worker: skipping non-mailto RUA {uri}");
                continue;
            }
            let Some(xml) = self.build(&c, &domain).await else {
                continue;
            };
            let now = chrono::Utc::now();
            let message_id = format!(
                "<dmarc-report-{domain}-{}@{}>",
                now.timestamp(),
                self.hostname
            );
            let raw = raw_message(
                &self.hostname,
                &email,
                &domain,
                &message_id,
                &xml,
                &now.format("%a, %d %b %Y %H:%M:%S +0000").to_string(),
                &format!("dmarc-{}", now.timestamp_nanos_opt().unwrap_or(0)),
            );
            let from = format!("dmarc-reports@{}", self.hostname);
            let rcpts = vec![email.clone()];
            if let Err(e) = c
                .execute(
                    "INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status) \
                     VALUES ($1, $2, $3, $4, 'pending')",
                    &[
                        (&message_id, Type::TEXT),
                        (&from, Type::TEXT),
                        (&rcpts, Type::TEXT_ARRAY),
                        (&raw, Type::TEXT),
                    ],
                )
                .await
            {
                warn(&format!("enqueue failed for {domain}"), e);
                continue;
            }
            // Go ignores the DELETE's error.
            let _ = c
                .execute(
                    "DELETE FROM dmarc_reports WHERE domain = $1",
                    &[(&domain, Type::TEXT)],
                )
                .await;
        }
    }

    /// `buildAggregateXML`: `None` is Go's "no data to report" (or a failed build).
    async fn build(&self, c: &WorkerConnection, domain: &str) -> Option<String> {
        let org = c
            .query(
                "SELECT COALESCE(policy_domain, domain) FROM dmarc_reports WHERE domain = $1 LIMIT 1",
                &[(&domain, Type::TEXT)],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, String>(0).ok()))
            .filter(|org| !org.is_empty())
            .unwrap_or_else(|| domain.to_owned());
        let rows = c
            .query(
                "SELECT COALESCE(SUM(total_count), 0)::bigint, COALESCE(SUM(count_fail), 0)::bigint, \
                 floor(EXTRACT(EPOCH FROM MIN(begin_time)))::bigint, floor(EXTRACT(EPOCH FROM MAX(end_time)))::bigint \
                 FROM dmarc_reports WHERE domain = $1",
                &[(&domain, Type::TEXT)],
            )
            .await
            .ok()?;
        let row = rows.first()?;
        let total = row.try_get::<_, i64>(0).ok()?;
        let failed = row.try_get::<_, i64>(1).ok()?;
        // A NULL begin/end (no rows) is Go's failed Scan: no data.
        let begin = row.try_get::<_, i64>(2).ok()?;
        let end = row.try_get::<_, i64>(3).ok()?;
        if total == 0 {
            return None;
        }
        Some(aggregate_xml(
            &org,
            &self.hostname,
            domain,
            chrono::Utc::now().timestamp(),
            begin,
            end,
            total,
            failed > 0,
        ))
    }
}
