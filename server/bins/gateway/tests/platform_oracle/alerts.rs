//! Group `alerts` cases for the `terms-remaining` oracle: `/admin/alerts*`. Go's own
//! health worker writes `minio_connectivity` rows while it runs, so every case clears
//! them right before its request; seeded rows use `plat5-*` check names and config keys.
use super::terms::Case;

const EFFECTS: &str = "SELECT j FROM (SELECT 1 k, check_name n, to_jsonb(a)::text j FROM health_alerts a WHERE check_name LIKE 'plat5-%' UNION ALL SELECT 2, key, to_jsonb(c)::text FROM system_config c WHERE key LIKE 'hc%' OR key LIKE 'alert%') x ORDER BY k, n";
const CLEAR: &str = "DELETE FROM health_history WHERE check_name='minio_connectivity'; DELETE FROM health_alerts WHERE check_name='minio_connectivity'";
const CONFIG_CLEANUP: &str = "DELETE FROM system_config WHERE key LIKE 'plat5%'; DELETE FROM system_config WHERE (key LIKE 'hc%' OR key LIKE 'alert%') AND description IS DISTINCT FROM (SELECT description FROM (VALUES ('x')) v(description) WHERE false) AND key NOT IN ('alert_email_addresses','alert_min_consecutive','hc_auth_fail_error','hc_auth_fail_warn','hc_consec_fail_window_min','hc_crash_window_min','hc_db_size_error_gb','hc_db_size_warn_gb','hc_dkim_expiry_error_days','hc_dkim_expiry_warn_days','hc_outbound_queue_age_error_min','hc_outbound_queue_age_warn_min','hc_outbound_queue_error','hc_outbound_queue_warn','hc_replication_lag_error_sec','hc_replication_lag_warn_sec')";
/// The schema's own rows are restored to their seeded values after a case rewrote them.
const RESTORE: &str = "UPDATE system_config SET value='\"3\"'::jsonb WHERE key='alert_min_consecutive'; UPDATE system_config SET value='\"\"'::jsonb WHERE key='alert_email_addresses'; UPDATE system_config SET value='\"100\"'::jsonb WHERE key='hc_db_size_warn_gb'";
/// What a case leaves behind: the schema's seeded 80. The goldens of these cases start from the
/// 100 `RESTORE` writes, but every other suite (platform_config, ...) expects the seed (#472).
const LEAVE_SEEDED: &str = "UPDATE system_config SET value='\"3\"'::jsonb WHERE key='alert_min_consecutive'; UPDATE system_config SET value='\"\"'::jsonb WHERE key='alert_email_addresses'; UPDATE system_config SET value='\"80\"'::jsonb WHERE key='hc_db_size_warn_gb'";

fn history(null_minutes_ago: i64) -> String {
    let rows = [
        // disk: four newest errors after an ok.
        ("plat5-disk", "10:00:00", "ok", "fine"),
        ("plat5-disk", "10:01:00", "error", "e1"),
        ("plat5-disk", "10:02:00", "error", "e2"),
        ("plat5-disk", "10:03:00", "error", "e3"),
        ("plat5-disk", "10:04:00", "error", "disk <full> & \u{2028}"),
        // mail: only two errors.
        ("plat5-mail", "10:05:00", "error", "m1"),
        ("plat5-mail", "10:06:00", "error", "m2"),
        // dns: newest is ok, so no streak.
        ("plat5-dns", "10:00:30", "error", "d1"),
        ("plat5-dns", "10:01:30", "error", "d2"),
        ("plat5-dns", "10:02:30", "error", "d3"),
        ("plat5-dns", "10:07:00", "ok", "back"),
        // empty details are omitted from the output.
        ("plat5-empty", "10:08:00", "error", ""),
        ("plat5-empty", "10:09:00", "error", ""),
        ("plat5-empty", "10:10:00", "error", ""),
        // exactly three errors, the acknowledged one.
        ("plat5-acked", "10:11:00", "error", "a1"),
        ("plat5-acked", "10:12:00", "error", "a2"),
        ("plat5-acked", "10:13:00", "error", "a3"),
        // a warn in the middle breaks the streak.
        ("plat5-warn", "10:14:00", "error", "w1"),
        ("plat5-warn", "10:15:00", "warn", "w2"),
        ("plat5-warn", "10:16:00", "error", "w3"),
        ("plat5-warn", "10:17:00", "error", "w4"),
    ];
    // Go's health worker prunes old history, so the rows are minutes old, ordered as listed.
    let ago = |t: &str| {
        let minutes: i64 = t[3..5].parse().unwrap_or(0);
        format!("now() - interval '{} minutes'", 40 - minutes)
    };
    let values: Vec<String> = rows
        .iter()
        .map(|(n, t, s, d)| format!("({},'{n}','{s}','{d}')", ago(t)))
        .collect();
    // A NULL last error does not scan into Go's string: the row is skipped.
    format!(
        "INSERT INTO health_history(checked_at,check_name,status,details) VALUES {}, (now() - interval '{{n0}} minutes','plat5-null','error',NULL),(now() - interval '{{n1}} minutes','plat5-null','error',NULL),(now() - interval '{{n2}} minutes','plat5-null','error',NULL); INSERT INTO health_alerts(check_name,alert_sent_at,suppressed,acknowledged_at,created_at,updated_at) VALUES ('plat5-acked','2026-10-01 11:00:00+00',true,'2026-10-01 11:30:00+00','2026-10-01 11:00:00+00','2026-10-01 11:30:00+00'),('plat5-disk','2026-10-01 10:30:00+00',false,NULL,'2026-10-01 10:30:00+00','2026-10-01 10:30:00+00')",
        values.join(",")
    )
    .replace("{n0}", &null_minutes_ago.to_string())
    .replace("{n1}", &(null_minutes_ago - 1).to_string())
    .replace("{n2}", &(null_minutes_ago - 2).to_string())
}

fn base(method: &'static str, pattern: &'static str, perm: &'static str, status: u16) -> Case {
    Case {
        method,
        pattern,
        fill: vec![],
        query: String::new(),
        perm,
        body: String::new(),
        headers: vec![],
        // RESTORE first: the schema seeds `hc_db_size_warn_gb` at 80, the goldens were recorded at
        // the 100 a previous case's cleanup leaves behind, so a fresh database must start there.
        seed: vec![CLEAR.into(), RESTORE.into()],
        cleanup: vec![
            "DELETE FROM health_history WHERE check_name LIKE 'plat5-%'".into(),
            "DELETE FROM health_alerts WHERE check_name LIKE 'plat5-%'".into(),
            CONFIG_CLEANUP.into(),
            LEAVE_SEEDED.into(),
        ],
        effects: EFFECTS,
        table: "health_alerts",
        channels: vec![],
        status,
        replace: vec![],
        unshift: vec![],
    }
}

pub fn specs(action: &str, label: &str) -> Option<Case> {
    let mut c = match action {
        "alerts-list" => base("GET", "/admin/alerts", "audit.read", 200),
        "alerts-ack" => base("POST", "/admin/alerts/ack", "security.write", 204),
        "alerts-unsuppress" => base("POST", "/admin/alerts/unsuppress", "security.write", 204),
        "alerts-config-get" => base("GET", "/admin/alerts/config", "audit.read", 200),
        "alerts-config-set" => base("PUT", "/admin/alerts/config", "security.write", 204),
        _ => return None,
    };
    match action {
        "alerts-list" => {
            // A NULL last error does not scan into Go's string and pgx then stops the rows:
            // oldest in the list it only drops itself; newest it empties the answer.
            let null_age = match label {
                "scan-failure-first" => 22,
                "scan-failure-middle" => 33,
                _ => 55,
            };
            if label != "empty" {
                c.seed.push(history(null_age));
            }
            match label {
                "success"
                | "empty"
                | "denied"
                | "scoped"
                | "scan-failure-first"
                | "scan-failure-middle" => {}
                "ignored-query" => c.query = "?limit=1&x=%zz".into(),
                "minio-streak" => {
                    // A streak made of a worker-style check with a long error text.
                    c.seed.push("INSERT INTO health_history(checked_at,check_name,status,details) VALUES (now() - interval '3 minutes','plat5-long','error','x'),(now() - interval '2 minutes','plat5-long','error','y'),(now() - interval '1 minute','plat5-long','error','z')".into());
                }
                _ => return None,
            }
        }
        "alerts-ack" | "alerts-unsuppress" => {
            c.seed.push("INSERT INTO health_alerts(check_name,alert_sent_at,suppressed,acknowledged_at,created_at,updated_at) VALUES ('plat5-existing','2026-10-01 11:00:00+00',false,NULL,'2026-10-01 11:00:00+00','2026-10-01 11:00:00+00'),('plat5-held','2026-10-01 11:00:00+00',true,'2026-10-01 11:30:00+00','2026-10-01 11:00:00+00','2026-10-01 11:30:00+00')".into());
            let named = |n: &str| format!("{{\"checkName\":{n}}}");
            c.body = named("\"plat5-new\"");
            match label {
                "success" | "denied" | "scoped" | "repeat" => {}
                "existing" => c.body = named("\"plat5-existing\""),
                "held" => c.body = named("\"plat5-held\""),
                "folded" => c.body = r#"{"CHECKNAME":"plat5-folded"}"#.into(),
                "unknown-key" => {
                    c.body = r#"{"checkName":"plat5-extra","x":[1,{"a":null}]}"#.into()
                }
                "duplicate-key" => {
                    c.body = r#"{"checkName":"plat5-first","checkName":"plat5-second"}"#.into()
                }
                "trailing-data" => c.body = r#"{"checkName":"plat5-trail"} {"x":1}"#.into(),
                "trailing-junk" => c.body = r#"{"checkName":"plat5-junk"} garbage"#.into(),
                "escaped" => c.body = named("\"plat5-<a>&\\u2028\""),
                "long-name" => c.body = named(&format!("\"plat5-{}\"", "n".repeat(5000))),
                "bad-json" => c.body = "{\"checkName\":".into(),
                "empty-body" => c.body = String::new(),
                "null-body" => c.body = "null".into(),
                "array-body" => c.body = "[1]".into(),
                "string-body" => c.body = "\"x\"".into(),
                "missing" => c.body = "{}".into(),
                "empty-name" => c.body = named("\"\""),
                "null-name" => c.body = named("null"),
                "number-name" => c.body = named("5"),
                "nul-name" => c.body = named("\"plat5-a\\u0000b\""),
                "null-then-value" => c.body = r#"{"checkName":null,"checkName":"plat5-nv"}"#.into(),
                "value-then-null" => c.body = r#"{"checkName":"plat5-vn","checkName":null}"#.into(),
                _ => return None,
            }
            if action == "alerts-unsuppress" && label == "success" {
                c.body = named("\"plat5-held\"");
            }
        }
        "alerts-config-get" => {
            let seeds = "INSERT INTO system_config(key,value,description,updated_at) VALUES ('hc_plat5_string','\"v\"','d','2026-10-01 10:00:00+00'),('hc_plat5_number','12.50','d','2026-10-01 10:00:00+00'),('alert_plat5_object','{\"b\":[1,2,{\"c\":null}],\"a\":\"<x>\"}','d','2026-10-01 10:00:00+00'),('alert_plat5_null','null','d','2026-10-01 10:00:00+00'),('alert_plat5_bool','true','d','2026-10-01 10:00:00+00'),('hcXplat5_wild','\"w\"','d','2026-10-01 10:00:00+00'),('alertXplat5_wild','\"w\"','d','2026-10-01 10:00:00+00'),('hc','\"short\"','d','2026-10-01 10:00:00+00'),('hc_','\"just-prefix\"','d','2026-10-01 10:00:00+00'),('plat5_hc_other','\"not-listed\"','d','2026-10-01 10:00:00+00'),('hc_plat5_unicode','\"\u{e9}\u{2028}\"','d','2026-10-01 10:00:00+00')";
            c.seed.push(seeds.into());
            match label {
                "success" | "denied" | "scoped" => {}
                "defaults-only" => {
                    c.seed.pop();
                }
                "ignored-query" => c.query = "?prefix=hc&x=%zz".into(),
                _ => return None,
            }
            c.table = "system_config";
        }
        "alerts-config-set" => {
            c.table = "system_config";
            c.seed.push("INSERT INTO system_config(key,value,description,updated_at) VALUES ('hc_plat5_existing','\"old\"','keep this description','2026-10-01 10:00:00+00')".into());
            c.body = r#"{"hc_plat5_a":"text","hc_plat5_existing":"new","alert_plat5_b":5}"#.into();
            match label {
                "success" | "denied" | "scoped" | "repeat" => {}
                "numbers" => c.body = r#"{"hc_plat5_int":1,"hc_plat5_float":1.0,"hc_plat5_exp":1e2,"hc_plat5_small":0.000001,"hc_plat5_tiny":1e-7,"hc_plat5_big":100000000000000000000,"hc_plat5_huge":1e21,"hc_plat5_neg":-12.5,"hc_plat5_negzero":-0,"hc_plat5_longfrac":0.1234567890123456789,"hc_plat5_maxint":9223372036854775807}"#.into(),
                "structures" => c.body = r#"{"hc_plat5_obj":{"z":1,"a":{"y":[1,2.0,"s",null,true]}},"hc_plat5_arr":[3,2,1],"hc_plat5_null":null,"hc_plat5_bool":false,"hc_plat5_str":"<a>& é"}"#.into(),
                "empty-object" => c.body = "{}".into(),
                "null-body" => c.body = "null".into(),
                "overwrite-defaults" => c.body = r#"{"alert_min_consecutive":"5","alert_email_addresses":"a@b.test","hc_db_size_warn_gb":90}"#.into(),
                "duplicate-key" => c.body = r#"{"hc_plat5_dup":1,"hc_plat5_dup":2}"#.into(),
                "bad-key" => c.body = r#"{"password_min_length":3}"#.into(),
                "mixed-bad-key" => c.body = r#"{"hc_plat5_ok":1,"identity_source":"x"}"#.into(),
                "uppercase-prefix" => c.body = r#"{"HC_plat5_up":1}"#.into(),
                "prefix-only" => c.body = r#"{"hc_":1,"alert_":2}"#.into(),
                "empty-key" => c.body = r#"{"":1}"#.into(),
                "similar-prefix" => c.body = r#"{"hcx_plat5":1}"#.into(),
                "folded-key-not-allowed" => c.body = r#"{"Alert_plat5":1}"#.into(),
                "bad-json" => c.body = "{\"hc_a\":".into(),
                "empty-body" => c.body = String::new(),
                "array-body" => c.body = "[1]".into(),
                "string-body" => c.body = "\"x\"".into(),
                "number-body" => c.body = "5".into(),
                "huge-number" => c.body = r#"{"hc_plat5_h":1e999}"#.into(),
                "nul-key" => c.body = r#"{"hc_plat5_\u0000k":1}"#.into(),
                "nul-value" => c.body = r#"{"hc_plat5_nv":"a\u0000b"}"#.into(),
                "trailing-data" => c.body = r#"{"hc_plat5_t":1} {"x":2}"#.into(),
                "trailing-junk" => c.body = r#"{"hc_plat5_j":1} junk"#.into(),
                "atomic-failure" => c.body = r#"{"hc_plat5_first":1,"hc_plat5_second":"a\u0000b"}"#.into(),
                "large-value" => c.body = format!("{{\"hc_plat5_large\":\"{}\"}}", "x".repeat(200_000)),
                _ => return None,
            }
        }
        _ => return None,
    }
    c.status = if label == "denied" { 403 } else { 0 };
    Some(c)
}
