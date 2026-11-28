//! Group `monitor` cases for the `terms-remaining` oracle: `/admin/monitor/live` and
//! `/admin/reports/summary`. Seeds are relative to `now()` at offsets that fall on
//! distinct UTC days (1, 27, 53, 79 and 200 hours ago); the run masks the resulting dates.
use super::terms::Case;

pub const OFFSETS: [i64; 5] = [1, 27, 53, 79, 200];
const NONE: &str = "SELECT '{}' WHERE false";

fn ago(hours: i64) -> String {
    format!("now() - interval '{hours} hours'")
}

/// Counts are chosen so no ranking has a tie (Postgres orders ties arbitrarily): in the
/// last hour senders are a 7, b 3, c 1 and recipients b 5, a 3, c 2, d 1; older buckets add
/// to those without equalling them.
fn trace() -> String {
    let mut rows: Vec<(&str, &str, &str, i64, &str)> = vec![];
    let mut push = |count: usize, event, from, to, hours, details| {
        for _ in 0..count {
            rows.push((event, from, to, hours, details));
        }
    };
    push(5, "received", "alice@x.test", "bob@y.test", 1, "null");
    push(2, "received", "alice@x.test", "carol@y.test", 1, "null");
    push(3, "delivered", "bob@y.test", "alice@x.test", 1, "null");
    push(1, "deferred", "carol@y.test", "dave@z.test", 1, "null");
    push(1, "bounced", "bob@y.test", "gone@z.test", 1, "null");
    push(
        1,
        "spam_filtered",
        "spam@bad.test",
        "alice@x.test",
        1,
        "null",
    );
    push(
        2,
        "rule_applied",
        "alice@x.test",
        "bob@y.test",
        1,
        r#"'{"rule_name":"tag-it"}'"#,
    );
    push(1, "rule_applied", "alice@x.test", "bob@y.test", 1, "'{}'");
    push(1, "received", "alice@x.test", "bob@y.test", 27, "null");
    push(1, "delivered", "bob@y.test", "alice@x.test", 27, "null");
    push(1, "bounced", "alice@x.test", "bob@y.test", 53, "null");
    push(1, "received", "alice@x.test", "carol@y.test", 79, "null");
    push(1, "delivered", "bob@y.test", "alice@x.test", 200, "null");
    push(
        3,
        "rule_applied",
        "old@x.test",
        "bob@y.test",
        200,
        r#"'{"rule_name":"old-rule"}'"#,
    );
    let values: Vec<String> = rows
        .iter()
        .enumerate()
        .map(|(i, (event, from, to, h, details))| {
            let details = if *details == "null" {
                "NULL".to_owned()
            } else {
                details.to_string()
            };
            format!(
                "('plat5-{i}','{event}','{from}','{to}',{details},{})",
                ago(*h)
            )
        })
        .collect();
    format!(
        "INSERT INTO message_trace(message_id,event,from_addr,rcpt_addr,details,occurred_at) VALUES {}",
        values.join(",")
    )
}

fn live_seeds() -> Vec<String> {
    let end = "date_trunc('day', now() AT TIME ZONE 'UTC')";
    vec![
        "INSERT INTO domains(id,name,dmarc_policy,created_at,updated_at) VALUES (9501,'plat5-known.test','reject','2026-10-01 10:00:00+00','2026-10-01 10:00:00+00')".into(),
        format!("INSERT INTO dmarc_reports(domain,report_uri,begin_time,end_time,count_none,count_pass,count_fail,count_temperror) VALUES ('plat5-known.test','plat5-1',{end} - interval '1 day',{end},1,5,2,3),('plat5-known.test','plat5-2',{end} - interval '2 days',{end},0,4,1,0),('plat5-unknown.test','plat5-3',{end} - interval '1 day',{end},2,0,7,1),('plat5-old.test','plat5-4',{end} - interval '2 days',{end} - interval '1 day',9,9,9,9)"),
        "INSERT INTO outbound_queue(message_id,from_addr,rcpt_addrs,raw_ref,status,queued_at) VALUES ('plat5-q1','a@x.test','{b@y.test}','ref','pending',now()),('plat5-q2','a@x.test','{b@y.test}','ref','pending',now()),('plat5-q3','a@x.test','{b@y.test}','ref','deferred',now() - interval '30 hours'),('plat5-q4','a@x.test','{b@y.test}','ref','delivered',now()),('plat5-q5','a@x.test','{b@y.test}','ref','bounced',now()),('plat5-q6','a@x.test','{b@y.test}','ref','bounced',now() - interval '40 hours')".into(),
        "INSERT INTO quarantined_messages(message_id,mailbox_id,original_tag,reason,virus_name,quarantined_at,released_at,rejected_at) VALUES ({a_msg1},{a_mailbox},'plat5','r','EICAR',now(),NULL,NULL),({a_msg2},{a_mailbox},'plat5','r','EICAR',now() - interval '2 days',NULL,NULL),({a_msg1},{a_mailbox},'plat5','r','Worm.A',now() - interval '3 days',now(),NULL),({a_msg2},{a_mailbox},'plat5','r',NULL,now() - interval '9 days',NULL,now()),({a_msg2},{a_mailbox},'plat5','r','Old.Virus',now() - interval '9 days',NULL,NULL)".into(),
    ]
}

pub fn specs(action: &str, label: &str) -> Option<Case> {
    let (method, pattern, perm) = match action {
        "monitor-live" => ("GET", "/admin/monitor/live", "domains.read"),
        "reports-summary" => ("GET", "/admin/reports/summary", "reports.read"),
        _ => return None,
    };
    let mut c = Case {
        method,
        pattern,
        fill: vec![],
        query: String::new(),
        perm,
        body: String::new(),
        headers: vec![],
        seed: vec![],
        cleanup: vec![
            "DELETE FROM quarantined_messages WHERE original_tag='plat5'".into(),
            "DELETE FROM outbound_queue WHERE message_id LIKE 'plat5-%'".into(),
            "DELETE FROM dmarc_reports WHERE report_uri LIKE 'plat5-%'".into(),
            "DELETE FROM message_trace WHERE message_id LIKE 'plat5-%'".into(),
            "DELETE FROM domains WHERE id=9501".into(),
        ],
        effects: NONE,
        table: "none",
        channels: vec![],
        status: if label == "denied" { 403 } else { 200 },
        replace: vec![],
        unshift: vec![],
    };
    match action {
        "monitor-live" => {
            if label != "empty-db" {
                c.seed = live_seeds();
            }
            match label {
                "success" | "denied" | "scoped" | "empty-db" => {}
                "sections-dmarc" => c.query = "?sections=dmarc".into(),
                "sections-queue" => c.query = "?sections=queue".into(),
                "sections-quarantine" => c.query = "?sections=quarantine".into(),
                "sections-volume" => c.query = "?sections=volume".into(),
                "sections-threats" => c.query = "?sections=threats".into(),
                "sections-system" => c.query = "?sections=system".into(),
                "sections-two" => c.query = "?sections=queue,volume".into(),
                "sections-substring" => c.query = "?sections=xxdmarcxx".into(),
                "sections-unknown" => c.query = "?sections=bogus".into(),
                "sections-case" => c.query = "?sections=QUEUE".into(),
                "sections-empty" => c.query = "?sections=".into(),
                "sections-repeated" => c.query = "?sections=queue&sections=system".into(),
                "ignored-query" => c.query = "?x=%zz&sections=queue&y=%00".into(),
                _ => return None,
            }
        }
        "reports-summary" => {
            if label != "empty" {
                c.seed = vec![trace()];
            }
            match label {
                "success" | "denied" | "scoped" | "empty" => {}
                "days-1" => c.query = "?days=1".into(),
                "days-2" => c.query = "?days=2".into(),
                "days-3" => c.query = "?days=3".into(),
                "days-90" => c.query = "?days=90".into(),
                "days-91" => c.query = "?days=91".into(),
                "days-0" => c.query = "?days=0".into(),
                "days-negative" => c.query = "?days=-5".into(),
                "days-bad" => c.query = "?days=abc".into(),
                "days-float" => c.query = "?days=1.5".into(),
                "days-plus" => c.query = "?days=%2B5".into(),
                "days-padded" => c.query = "?days=003".into(),
                "days-huge" => c.query = "?days=99999999999999999999".into(),
                "days-empty" => c.query = "?days=".into(),
                "days-space" => c.query = "?days=%205".into(),
                "days-repeated" => c.query = "?days=2&days=3".into(),
                "ignored-query" => c.query = "?x=%zz&days=2&y=%00".into(),
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(c)
}
