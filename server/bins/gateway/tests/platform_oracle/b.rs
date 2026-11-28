//! Platform oracle, group 1b (#443): health, features, sod-mode, welcome-email, jit-defaults
//! and auth-methods. Everything action-specific lives here: the request a `(action, label)`
//! pair sends, the persona it needs, the rows it seeds (and how they are restored) and the
//! table state the observation records. `mod.rs` owns the Go/Rust harness.
use super::rows;
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

pub fn handles(action: &str) -> bool {
    route(action).is_some()
}

/// `(method, inventory pattern)` of a 1b action.
pub fn route(action: &str) -> Option<(&'static str, &'static str)> {
    Some(match action {
        "admin-health" => ("GET", "/admin/health"),
        "features-list" => ("GET", "/admin/features"),
        "features-set" => ("PUT", "/admin/features/{key}"),
        "features-delete" => ("DELETE", "/admin/features/{key}"),
        "features-mode" => ("PUT", "/admin/features/registry-mode"),
        "sod-get" => ("GET", "/admin/dengbao/sod-mode"),
        "sod-set" => ("PUT", "/admin/dengbao/sod-mode"),
        "welcome-get" => ("GET", "/admin/system/welcome-email"),
        "welcome-put" => ("PUT", "/admin/system/welcome-email"),
        "welcome-test" => ("POST", "/admin/system/welcome-email/test"),
        "jit-get" => ("GET", "/admin/system/jit-defaults"),
        "jit-put" => ("PUT", "/admin/system/jit-defaults"),
        "auth-list" => ("GET", "/admin/auth/methods"),
        "auth-update" => ("PUT", "/admin/auth/methods/{slug}"),
        _ => return None,
    })
}

/// The permissions that satisfy an action's gate.
pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "admin-health" => vec!["queue.read"],
        "features-list" | "welcome-get" => vec!["backup.read"],
        "features-set" | "features-delete" | "features-mode" | "welcome-put" | "welcome-test" => {
            vec!["system.config"]
        }
        "sod-get" | "sod-set" => vec!["security.write"],
        "auth-list" => vec!["users.read"],
        "auth-update" => vec!["identity.write"],
        "jit-get" | "jit-put" => vec!["roles.manage"],
        _ => vec![],
    }
}

/// A permission set that never satisfies the gate.
pub fn denied(action: &str) -> Vec<&'static str> {
    match action {
        "auth-list" => vec!["queue.read"],
        _ => vec!["users.read"],
    }
}

/// The persona's `reason_required_areas` choice, as a label.
fn reason_area(action: &str, label: &str) -> Option<&'static str> {
    (label == "reason-area").then_some(if action == "sod-set" {
        "security"
    } else {
        "system"
    })
}

pub struct Wire {
    pub query: String,
    pub body: String,
    pub recorded_body: String,
    pub key: String,
    pub headers: Vec<(String, String)>,
}

fn is_write(action: &str) -> bool {
    matches!(
        action,
        "features-set"
            | "features-delete"
            | "features-mode"
            | "sod-set"
            | "welcome-put"
            | "welcome-test"
            | "jit-put"
            | "auth-update"
    )
}

const KEY: &str = "feature.stale_nudges";
const LEGACY: &str = "plat1b.legacy";
const FRESH: &str = "plat1b.fresh_key";

fn welcome_body(locales: &str) -> String {
    format!("{{\"enabled\":true,\"default_locale\":\"en\",\"locales\":{locales}}}")
}

pub fn wire(action: &str, label: &str) -> Wire {
    let same = |t: &str| (t.to_string(), t.to_string());
    let (body, recorded_body) = match (action, label) {
        ("features-set", l) => match l {
            "bad-json" => same("{\"enabled\":"),
            "unknown-field" => same("{\"enabled\":true,\"x\":1}"),
            "no-enabled" => same("{}"),
            "null-enabled" => same("{\"enabled\":null}"),
            "trailing" => same("{\"enabled\":true}{\"enabled\":false}"),
            "trailing-garbage" => same("{\"enabled\":true} x"),
            "typed" => same("{\"enabled\":\"yes\"}"),
            "folded" => same("{\"ENABLED\":false}"),
            "array" => same("[true]"),
            "oversize" => (
                format!("{{\"enabled\":true,{}}}", " ".repeat(9000)),
                "{\"enabled\":true,<9000 spaces>}".to_string(),
            ),
            "off" => same("{\"enabled\":false}"),
            _ => same("{\"enabled\":true}"),
        },
        ("features-mode", l) => match l {
            "enforce" | "enforce-unknown" | "enforce-skew" => same("{\"mode\":\"enforce\"}"),
            "invalid-mode" => same("{\"mode\":\"maybe\"}"),
            "bad-json" => same("{\"mode\":"),
            "unknown-field" => same("{\"mode\":\"observe\",\"x\":1}"),
            "empty-mode" => same("{}"),
            _ => same("{\"mode\":\"observe\"}"),
        },
        ("sod-set", l) => match l {
            "enable-violations" | "enable-clean" | "reason-area" => same("{\"enabled\":true}"),
            "bad-json" => same("{\"enabled\":"),
            "typed" => same("{\"enabled\":\"yes\"}"),
            "empty-object" => same("{}"),
            "folded" => same("{\"ENABLED\":false,\"x\":1} trailing"),
            _ => same("{\"enabled\":false}"),
        },
        ("welcome-put", l) => match l {
            "full" => same(&welcome_body(
                "{\"en\":{\"subject\":\"Hi {{DisplayName}} <&>\",\"body_text\":\"Text\\u2028 é\",\"body_html\":\"<p>x</p>\"},\"zh\":{\"subject\":\"你好\",\"body_text\":\"文本\"},\"de\":null}",
            )),
            "folded" => same("{\"ENABLED\":false,\"Default_Locale\":\"zh\",\"x\":1,\"LOCALES\":{\"en\":{\"SUBJECT\":\"s\",\"Body_Text\":\"b\"},\"zh\":{}}} trailing"),
            "bad-default" => same("{\"enabled\":true,\"default_locale\":\"fr\",\"locales\":{\"en\":{\"subject\":\"s\",\"body_text\":\"b\"}}}"),
            "no-en" => same(&welcome_body("{\"zh\":{\"subject\":\"s\",\"body_text\":\"b\"}}")),
            "empty-subject" => same(&welcome_body("{\"en\":{\"subject\":\"\",\"body_text\":\"b\"}}")),
            "empty-text" => same(&welcome_body("{\"en\":{\"subject\":\"s\",\"body_text\":\"\"}}")),
            "unknown-locale" => same(&welcome_body("{\"en\":{\"subject\":\"s\",\"body_text\":\"b\"},\"fr\":{\"subject\":\"s\"}}")),
            "null-locales" => same("{\"enabled\":true,\"default_locale\":\"en\",\"locales\":null}"),
            "bad-json" => same("{\"enabled\":"),
            "array" => same("[]"),
            "typed" => same("{\"enabled\":\"yes\"}"),
            "oversize" => (
                welcome_body(&format!("{{\"en\":{{\"subject\":\"s\",\"body_text\":\"{}\"}}}}", "x".repeat(1 << 20))),
                welcome_body("{\"en\":{\"subject\":\"s\",\"body_text\":\"<1 MiB of x>\"}}"),
            ),
            _ => same(&welcome_body("{\"en\":{\"subject\":\"Welcome\",\"body_text\":\"Hello\"}}")),
        },
        ("welcome-test", l) => match l {
            "no-subject" => same("{\"body_text\":\"b\"}"),
            "no-text" => same("{\"subject\":\"s\"}"),
            "bad-json" => same("{\"subject\":"),
            "typed" => same("{\"subject\":5}"),
            "folded" => same("{\"SUBJECT\":\"Hi {{DisplayName}}\",\"Body_Text\":\"b {{Email}}\",\"x\":1} trailing"),
            "placeholders" => same("{\"locale\":\"zh\",\"subject\":\"Hi {{DisplayName}} at {{OrgName}} {{Nope}}\",\"body_text\":\"{{Username}} {{Email}} {{WebmailURL}} {{displayname}}\",\"body_html\":\"<b>{{DisplayName}}</b> & co\"}"),
            "oversize" => (
                format!("{{\"subject\":\"s\",\"body_text\":\"{}\"}}", "x".repeat(1 << 20)),
                "{\"subject\":\"s\",\"body_text\":\"<1 MiB of x>\"}".to_string(),
            ),
            _ => same("{\"subject\":\"Test {{DisplayName}}\",\"body_text\":\"Body {{Email}}\"}"),
        },
        ("jit-put", l) => match l {
            "zero" => same("{\"defaultMaxDurationMinutes\":0,\"defaultRequireJustification\":true}"),
            "negative" => same("{\"defaultMaxDurationMinutes\":-5}"),
            "bad-json" => same("{\"defaultMaxDurationMinutes\":"),
            "overflow" => same("{\"defaultMaxDurationMinutes\":3000000000,\"defaultRequireJustification\":true}"),
            "typed" => same("{\"defaultMaxDurationMinutes\":\"x\"}"),
            "float" => same("{\"defaultMaxDurationMinutes\":1.5}"),
            "folded" => same("{\"DEFAULTMAXDURATIONMINUTES\":60,\"x\":1} trailing"),
            "oversize" => (
                format!("{{\"defaultMaxDurationMinutes\":60,\"p\":\"{}\"}}", "x".repeat(5000)),
                "{\"defaultMaxDurationMinutes\":60,\"p\":\"<5000 x>\"}".to_string(),
            ),
            "no-justification" => same("{\"defaultMaxDurationMinutes\":45}"),
            _ => same("{\"defaultMaxDurationMinutes\":90,\"defaultRequireJustification\":true}"),
        },
        ("auth-update", l) => match l {
            "priority" => same("{\"priority\":35}"),
            "config" => same("{\"config\":{\"b\":[1,2],\"a\":\"<&>\"}}"),
            "config-null" => same("{\"config\":null}"),
            "all" => same("{\"enabled\":true,\"priority\":5,\"config\":{\"k\":1}}"),
            "empty" => same("{}"),
            "null-fields" => same("{\"enabled\":null,\"priority\":null}"),
            "bad-json" => same("{\"enabled\":"),
            "typed" => same("{\"enabled\":\"yes\"}"),
            "overflow" => same("{\"priority\":3000000000}"),
            "float" => same("{\"priority\":1.5}"),
            "folded" => same("{\"ENABLED\":true,\"x\":1} trailing"),
            _ => same("{\"enabled\":true}"),
        },
        _ => (String::new(), String::new()),
    };
    let key = match (action, label) {
        ("features-set", "new-key" | "enforce-unknown") => FRESH,
        ("features-set", "sod-key") => "dengbao.sod_mode",
        ("features-set", "invalid-key") => "BadKey",
        ("features-set", _) => KEY,
        ("features-delete", "success") => LEGACY,
        ("features-delete", "absent") => FRESH,
        ("features-delete", "known") => "feature.imap",
        ("features-delete", "invalid-key") => "BadKey",
        ("features-delete", _) => LEGACY,
        ("auth-update", "missing-slug") => "nope",
        ("auth-update", _) => "saml",
        _ => "",
    };
    let mut headers = vec![];
    if is_write(action)
        && action != "welcome-put"
        && action != "welcome-test"
        && action != "jit-put"
        && action != "auth-update"
    {
        match (action, label) {
            (_, "no-reason" | "reason-area") => {}
            (_, "long-reason") => headers.push(("x-audit-reason".into(), "x".repeat(1025))),
            _ => headers.push(("x-audit-reason".into(), "plat1b oracle reason".into())),
        }
    }
    if matches!(
        action,
        "welcome-put" | "welcome-test" | "jit-put" | "auth-update"
    ) {
        headers.push(("x-audit-reason".into(), "plat1b oracle reason".into()));
    }
    let query = if label == "ignored-query" {
        "?limit=-1&q=%00&x=%zz".to_string()
    } else {
        String::new()
    };
    Wire {
        query,
        body,
        recorded_body,
        key: key.to_string(),
        headers,
    }
}

/// The status frozen Go answers (Go's answer is recorded; a mismatch fails the recording).
pub fn wanted(action: &str, label: &str) -> u16 {
    if label == "denied" {
        return 403;
    }
    let bad_input = matches!(
        label,
        "bad-json"
            | "unknown-field"
            | "no-enabled"
            | "null-enabled"
            | "trailing"
            | "trailing-garbage"
            | "typed"
            | "array"
            | "oversize"
            | "invalid-key"
            | "invalid-mode"
            | "empty-mode"
            | "no-reason"
            | "long-reason"
            | "reason-area"
            | "bad-default"
            | "no-en"
            | "empty-subject"
            | "empty-text"
            | "unknown-locale"
            | "null-locales"
            | "no-subject"
            | "no-text"
            | "zero"
            | "negative"
            | "float"
            | "null-fields"
    ) || (action == "auth-update" && label == "empty");
    match (action, label) {
        ("features-set", "sod-key") => 403,
        ("features-set", "enforce-unknown") => 409,
        ("features-delete", "known") => 409,
        ("features-mode", "enforce-unknown" | "enforce-skew") => 409,
        ("sod-set", "enable-violations") => 409,
        ("jit-put", "overflow") => 500,
        ("auth-update", "overflow") => 500,
        ("auth-update", "missing-slug") => 404,
        ("admin-health", "error") => 503,
        ("admin-health", "null-details") => 500,
        (_, _) if bad_input => 400,
        ("features-set" | "features-delete" | "welcome-put" | "auth-update", _) => 204,
        // Frozen Go's deliver() runs without a mailbox scope and RLS refuses it.
        ("welcome-test", _) => 500,
        _ => 200,
    }
}

/// `reason_required_areas` with the labelled area added.
fn policy(action: &str, label: &str) -> Option<String> {
    reason_area(action, label).map(|area| format!("{{office,{area}}}"))
}

async fn save(
    owner: &tokio_postgres::Client,
    table: &str,
    tag: &str,
    undo: &mut Vec<String>,
) -> Result<(), BoxError> {
    let name = format!("plat1b_save_{tag}_{}", table.replace('.', "_"));
    owner
        .batch_execute(&format!(
            "DROP TABLE IF EXISTS {name}; CREATE TABLE {name} AS TABLE {table}"
        ))
        .await?;
    undo.push(format!(
        "DELETE FROM {table}; INSERT INTO {table} SELECT * FROM {name}; DROP TABLE {name}"
    ));
    Ok(())
}

/// Seeds that must exist before Go starts (its toggle snapshot loads at boot) and the ones
/// that must follow it (Go's own start-up writes would otherwise replace them).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Before,
    After,
}

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    action: &str,
    label: &str,
    phase: Phase,
    recording: bool,
    undo: &mut Vec<String>,
) -> Result<(), BoxError> {
    let tag = a.user.to_string();
    let persona = format!("plat1-role-{}", a.user);
    match (phase, action) {
        (Phase::Before, "features-list" | "features-set" | "features-delete" | "features-mode") => {
            for table in ["feature_toggles", "feature_toggle_registry_state"] {
                owner
                    .batch_execute(&format!(
                        "DROP TABLE IF EXISTS plat1b_save_{tag}_{table}; CREATE TABLE plat1b_save_{tag}_{table} AS TABLE {table}"
                    ))
                    .await?;
            }
            // Observe mode first, so unknown rows can be dropped and re-inserted.
            undo.push("UPDATE feature_toggle_registry_state SET mode='observe'".into());
            undo.push(format!("DELETE FROM feature_toggles; INSERT INTO feature_toggles SELECT * FROM plat1b_save_{tag}_feature_toggles; DROP TABLE plat1b_save_{tag}_feature_toggles"));
            undo.push(format!("DELETE FROM feature_toggle_registry_state; INSERT INTO feature_toggle_registry_state SELECT * FROM plat1b_save_{tag}_feature_toggle_registry_state; DROP TABLE plat1b_save_{tag}_feature_toggle_registry_state"));
            owner
                .batch_execute(&format!(
                    "DELETE FROM feature_toggles WHERE key LIKE 'plat1b.%'; \
                     INSERT INTO feature_toggles(key,enabled,description) VALUES('{LEGACY}',true,'legacy <row>')"
                ))
                .await?;
            if action == "features-list" {
                owner
                    .batch_execute(
                        "DELETE FROM feature_toggles WHERE key IN ('feature.imap','feature.meet','feature.kerberos'); \
                         UPDATE feature_toggles SET description='desc <x> & y', enabled=NOT enabled WHERE key IN ('feature.drive','feature.dnssec')",
                    )
                    .await?;
            }
            if (action, label) == ("features-set", "enforce-unknown")
                || (action, label) == ("features-mode", "enforce")
                || (action, label) == ("features-mode", "enforce-skew")
            {
                owner
                    .batch_execute(&format!("DELETE FROM feature_toggles WHERE key='{LEGACY}'"))
                    .await?;
            }
            if (action, label) == ("features-mode", "enforce-skew") {
                owner
                    .batch_execute(&format!(
                        "UPDATE feature_toggle_registry_state SET registry_digest='{}'",
                        "ab".repeat(32)
                    ))
                    .await?;
            }
            if (action, label) == ("features-list", "enforce")
                || (action, label) == ("features-set", "enforce-unknown")
            {
                owner
                    .batch_execute("UPDATE feature_toggle_registry_state SET mode='enforce'")
                    .await?;
            }
        }
        (_, "features-list" | "features-set" | "features-delete" | "features-mode") => {}
        (Phase::Before, "sod-get" | "sod-set") => {
            save(owner, "feature_toggles", &tag, undo).await?;
            save(owner, "admin_role_groups", &tag, undo).await?;
            let n = undo.len();
            // Restoring role groups must not cascade through assignments: update in place.
            undo[n - 1] = format!(
                "UPDATE admin_role_groups g SET permissions=s.permissions, sod_class=s.sod_class FROM plat1b_save_{tag}_admin_role_groups s WHERE g.id=s.id; DROP TABLE plat1b_save_{tag}_admin_role_groups"
            );
            owner
                .execute(
                    "UPDATE admin_role_groups SET sod_class='security' WHERE name=$1",
                    &[&persona],
                )
                .await?;
            let clean = matches!(label, "clean" | "on" | "enable-clean" | "disable");
            if clean {
                owner
                    .execute(
                        "UPDATE admin_role_groups SET sod_class='system', permissions='{users.read}' WHERE name<>$1",
                        &[&persona],
                    )
                    .await?;
            }
            let on = matches!(label, "on" | "disable");
            owner
                .execute(
                    "INSERT INTO feature_toggles(key,enabled) VALUES('dengbao.sod_mode',$1) ON CONFLICT (key) DO UPDATE SET enabled=$1",
                    &[&on],
                )
                .await?;
        }
        (_, "sod-get" | "sod-set") => {}
        (Phase::Before, "welcome-get" | "welcome-put" | "welcome-test") => {
            save(owner, "system_config", &tag, undo).await?;
            let n = undo.len();
            undo[n - 1] = format!(
                "DELETE FROM system_config WHERE key='welcome_email'; INSERT INTO system_config SELECT * FROM plat1b_save_{tag}_system_config WHERE key='welcome_email'; DROP TABLE plat1b_save_{tag}_system_config"
            );
            if label == "shell" {
                owner
                    .execute("DELETE FROM system_config WHERE key='welcome_email'", &[])
                    .await?;
            } else if action == "welcome-get" {
                owner
                    .execute(
                        "UPDATE system_config SET value='{\"enabled\":true,\"default_locale\":\"zh\",\"locales\":{\"zh\":{\"subject\":\"你好 <b>\",\"body_text\":\"t & u\",\"body_html\":\"\"},\"en\":{\"subject\":\"Hello\",\"body_text\":\"x\",\"body_html\":\"<p>x</p>\"}}}'::jsonb, updated_by=NULL WHERE key='welcome_email'",
                        &[],
                    )
                    .await?;
            }
        }
        (_, "welcome-get" | "welcome-put" | "welcome-test") => {}
        (Phase::Before, "jit-get" | "jit-put") => {
            save(owner, "system_config", &tag, undo).await?;
            let n = undo.len();
            undo[n - 1] = format!(
                "DELETE FROM system_config WHERE key LIKE 'jit.default_%'; INSERT INTO system_config SELECT * FROM plat1b_save_{tag}_system_config WHERE key LIKE 'jit.default_%'; DROP TABLE plat1b_save_{tag}_system_config"
            );
            if label == "defaults" {
                owner
                    .execute(
                        "DELETE FROM system_config WHERE key LIKE 'jit.default_%'",
                        &[],
                    )
                    .await?;
            } else if action == "jit-get" {
                owner
                    .batch_execute("UPDATE system_config SET value='45'::jsonb WHERE key='jit.default_max_minutes'; UPDATE system_config SET value='true'::jsonb WHERE key='jit.default_require_justification'")
                    .await?;
            }
        }
        (_, "jit-get" | "jit-put") => {}
        (Phase::Before, "auth-list" | "auth-update") => {
            save(owner, "auth_methods", &tag, undo).await?;
            if action == "auth-list" {
                owner
                    .batch_execute("UPDATE auth_methods SET config_json='{\"z\":[1,{\"b\":true,\"a\":\"<&>\"}],\"a\":null}'::jsonb WHERE slug='oidc'")
                    .await?;
            }
        }
        (_, "auth-list" | "auth-update") => {}
        (Phase::After, "admin-health") => {
            save(owner, "health_history", &tag, undo).await?;
            // Go's own checker writes rows while it runs; only the seeded rows may exist.
            owner
                .batch_execute(&format!(
                    "DELETE FROM health_history; \
                     CREATE FUNCTION plat1b_health_block_{tag}() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NULL; END $f$; \
                     CREATE TRIGGER plat1b_health_block BEFORE INSERT ON health_history FOR EACH ROW EXECUTE FUNCTION plat1b_health_block_{tag}()"
                ))
                .await?;
            undo.insert(
                0,
                format!("DROP TRIGGER plat1b_health_block ON health_history; DROP FUNCTION plat1b_health_block_{tag}()"),
            );
            let hist: &[(&str, &str, &str, &str, &str, &str)] = &[
                (
                    "db",
                    "ok",
                    "12.5",
                    "NULL",
                    "'older'",
                    "2026-10-01T09:00:00Z",
                ),
                (
                    "db",
                    "warn",
                    "13",
                    "20",
                    "'newer <&>'",
                    "2026-10-01T10:00:00.123456Z",
                ),
                (
                    "queue",
                    "ok",
                    "NULL",
                    "NULL",
                    "'idle'",
                    "2026-10-01T10:00:00Z",
                ),
                ("disk", "ok", "0", "0", "''", "2026-10-01T11:00:00Z"),
                (
                    "big",
                    "ok",
                    "12345678901234567890.5",
                    "0.0000001",
                    "'wide'",
                    "2026-10-01T12:00:00Z",
                ),
            ];
            let mut sql = String::from("BEGIN; SET LOCAL session_replication_role=replica;");
            if label != "empty" {
                for (name, status, value, threshold, details, at) in hist {
                    sql += &format!("INSERT INTO health_history(check_name,status,value,threshold,details,checked_at) VALUES('{name}','{status}',{value},{threshold},{details},'{at}');");
                }
            }
            if label == "null-details" {
                sql += "INSERT INTO health_history(check_name,status,value,details,checked_at) VALUES('nulldetails','ok',1,NULL,'2026-10-01T11:00:00Z');";
            }
            if label == "error" {
                sql += "INSERT INTO health_history(check_name,status,details,checked_at) VALUES('smtp','error','refused','2026-10-01T13:00:00Z');";
            }
            owner.batch_execute(&(sql + "COMMIT;")).await?;
            if recording {
                // Go's readiness probe cached its first verdict for 5 s.
                tokio::time::sleep(std::time::Duration::from_millis(5500)).await;
            }
        }
        (_, "admin-health") => {}
        _ => {}
    }
    if phase == Phase::Before {
        if let Some(areas) = policy(action, label) {
            let original: String = owner
                .query_one(
                    "SELECT reason_required_areas::text FROM audit_policy WHERE id=1",
                    &[],
                )
                .await?
                .get(0);
            owner
                .execute(
                    "UPDATE audit_policy SET reason_required_areas=$1::text::text[] WHERE id=1",
                    &[&areas],
                )
                .await?;
            undo.push(format!(
                "UPDATE audit_policy SET reason_required_areas='{original}'::text[] WHERE id=1"
            ));
        }
    }
    Ok(())
}

/// The recorded table state: `(table, rows)` entries.
pub async fn effects(
    owner: &tokio_postgres::Client,
    a: &Account,
    action: &str,
) -> Result<Vec<(&'static str, Value)>, BoxError> {
    Ok(match action {
        "features-list" | "features-set" | "features-delete" | "features-mode" => vec![
            (
                "feature_toggles",
                json!(rows(owner, "SELECT jsonb_build_object('key',key,'enabled',enabled,'description',description)::text FROM feature_toggles WHERE key LIKE 'plat1b.%' OR key IN ('feature.stale_nudges','feature.imap','dengbao.sod_mode') ORDER BY key").await?),
            ),
            (
                "feature_toggle_registry_state",
                json!(rows(owner, "SELECT jsonb_build_object('mode',mode,'registry_digest',registry_digest)::text FROM feature_toggle_registry_state").await?),
            ),
        ],
        "sod-get" | "sod-set" => vec![(
            "feature_toggles",
            json!(rows(owner, "SELECT jsonb_build_object('key',key,'enabled',enabled)::text FROM feature_toggles WHERE key='dengbao.sod_mode'").await?),
        )],
        "welcome-get" | "welcome-put" => vec![(
            "system_config",
            json!(rows(owner, "SELECT jsonb_build_object('key',key,'value',value,'encrypted',encrypted,'updated_by',updated_by)::text FROM system_config WHERE key='welcome_email'").await?),
        )],
        "welcome-test" => vec![(
            "messages",
            json!(
                owner
                    .query(
                        "SELECT jsonb_build_object('subject',subject,'body_text',body_text,'body_html',body_html,'from_addr',regexp_replace(from_addr,'@.*','@<domain>'),'from_name',from_name,'rcpt',regexp_replace(to_addrs::text,'@[^\"]*','@<domain>'),'raw_ref',regexp_replace(raw_ref,'[0-9]+$','<user>'),'message_id',regexp_replace(message_id,'-[0-9]+-[0-9]+@','-<user>-<nanos>@'),'size_bytes',size_bytes,'has_attachments',has_attachments)::text FROM messages WHERE mailbox_id=$1 AND raw_ref LIKE 'system:welcome:%' ORDER BY id",
                        &[&a.mailbox],
                    )
                    .await?
                    .iter()
                    .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
                    .collect::<Result<Vec<_>, _>>()?
            ),
        )],
        "jit-get" | "jit-put" => vec![(
            "system_config",
            json!(rows(owner, "SELECT jsonb_build_object('key',key,'value',value,'encrypted',encrypted,'updated_by',updated_by)::text FROM system_config WHERE key LIKE 'jit.default_%' ORDER BY key").await?),
        )],
        "auth-list" | "auth-update" => vec![(
            "auth_methods",
            json!(rows(owner, "SELECT jsonb_build_object('slug',slug,'name',name,'enabled',enabled,'priority',priority,'config_json',config_json)::text FROM auth_methods ORDER BY priority, slug").await?),
        )],
        "admin-health" => vec![(
            "health_history",
            json!(rows(owner, "SELECT jsonb_build_object('check_name',check_name,'status',status,'value',value,'details',details)::text FROM health_history ORDER BY check_name, checked_at").await?),
        )],
        _ => vec![],
    })
}

/// Run-specific text in a response body.
pub fn normalize(a: &Account, action: &str, text: &str) -> String {
    let text = text.replace(&format!("plat1-role-{}", a.user), "<role>");
    if !matches!(action, "sod-get" | "sod-set") {
        return text;
    }
    sod_canonical(&text)
}

/// `admin_sod_precheck()` has no ORDER BY: its row order follows the heap, which differs
/// between runs. The goldens were recorded with the violations split on `},{` and sorted, which
/// moves the first item's `{` and the last item's `}` with the heap order. Both sides are put in
/// one canonical form: braces dropped, items sorted by subject, the removed braces padded back
/// at the end so the byte length (and `content-length`) is unchanged.
pub fn sod_canonical(text: &str) -> String {
    let (Some(start), Some(end)) = (text.find("\"violations\":["), text.rfind("]}")) else {
        return text.to_owned();
    };
    let head = start + "\"violations\":[".len();
    if head >= end {
        return text.to_owned();
    }
    let body = &text[head..end];
    let flat: String = body.chars().filter(|c| *c != '{' && *c != '}').collect();
    let removed = body.len() - flat.len();
    let marker = ",\"violationType\"";
    let flat = format!(",{flat}");
    let mut items: Vec<&str> = flat.split(marker).skip(1).collect();
    items.sort_by_key(|item| item.split("\"subject\":").nth(1).unwrap_or("").to_owned());
    let joined: String = items.iter().map(|item| format!("{marker}{item}")).collect();
    format!(
        "{}{}{}{}",
        &text[..head],
        &joined[1..],
        "_".repeat(removed),
        &text[end..]
    )
}

/// Channels whose notifications the observation records.
pub fn channels(action: &str) -> &'static [&'static str] {
    match action {
        "welcome-test" => &[
            "config_changed",
            "mailbox_state",
            "mail_deliver",
            "jmap_state",
        ],
        _ => &["admin:alert", "backup_run", "config_changed"],
    }
}
