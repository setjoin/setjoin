//! Fixtures and the request each (action, label) case sends.
use crate::common::BoxError;
use setjoin_conformance::fixture::{self, Account};
use tokio_postgres::Client;

pub const D1: &str = "00000000-0000-4000-8000-00000000d001";
pub const D2: &str = "00000000-0000-4000-8000-00000000d002";
pub const D3: &str = "00000000-0000-4000-8000-00000000d003";
pub const D4: &str = "00000000-0000-4000-8000-00000000d004";
pub const D_ALL: [&str; 4] = [D1, D2, D3, D4];
const UUIDS: [&str; 4] = D_ALL;
pub const L1: i64 = 960001;
pub const L2: i64 = 960002;
pub const L3: i64 = 960003;
pub const L4: i64 = 960004;
pub const L_ALL: [i64; 4] = [L1, L2, L3, L4];
const LS: [i64; 4] = L_ALL;
pub const P1: i64 = 970001;
pub const P2: i64 = 970002;
pub const P3: i64 = 970003;
const NEXT_POLICY: i64 = 970100;
pub const MISSING: i64 = 999_999_999;

pub struct Fx {
    pub a: Account,
    pub b: Account,
    pub role: i64,
    pub a_domain: String,
    pub b_domain: String,
    /// `mdm_policies` rows the case replaced, put back on removal.
    pub saved: String,
}

pub struct Plan {
    pub method: &'static str,
    pub pattern: &'static str,
    pub path: String,
    pub query: String,
    pub body: String,
    pub recorded_body: String,
    /// Send the request once before the observed one.
    pub repeat: bool,
    pub head: bool,
}

pub fn is_read(action: &str) -> bool {
    matches!(
        action,
        "mdm-devices" | "mdm-device" | "policies" | "queue" | "devices-list"
    )
}

/// Governed permissions and whether the admin is scoped to its own domain.
pub fn access(action: &str, label: &str) -> (Vec<&'static str>, bool) {
    let read = is_read(action);
    let perms = match label {
        "denied" => vec!["users.read"],
        "wrong-perm" => {
            if read {
                vec!["mam.write"]
            } else {
                vec!["mam.read"]
            }
        }
        _ if read => vec!["mam.read"],
        _ => vec!["mam.write"],
    };
    (
        perms,
        matches!(label, "foreign" | "foreign-own" | "foreign-target"),
    )
}

pub fn root_secret() -> &'static str {
    "seed-secret"
}

impl Fx {
    pub async fn build(c: &Client, label: &str, action: &str) -> Result<Fx, BoxError> {
        // A previous aborted run may have left fixed-id rows behind.
        clear_fixed(c).await?;
        let a = fixture::account(c, "dev1-admin").await?;
        let b = fixture::account(c, "dev1-other").await?;
        let name = |d: i64| async move {
            Ok::<String, BoxError>(
                c.query_one("SELECT name FROM domains WHERE id=$1", &[&d])
                    .await?
                    .get(0),
            )
        };
        let (a_domain, b_domain) = (name(a.domain).await?, name(b.domain).await?);
        let (perms, scoped) = access(action, label);
        let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
        let scope: Option<i64> = scoped.then_some(a.domain);
        let role: i64 = c
            .query_one(
                "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ($1,$2,$3) RETURNING id",
                &[&format!("dev1-role-{}", a.user), &perms, &scope],
            )
            .await?
            .get(0);
        c.execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
        let saved: String = c
            .query_one(
                "SELECT COALESCE(jsonb_agg(to_jsonb(p)),'[]'::jsonb)::text FROM mdm_policies p",
                &[],
            )
            .await?
            .get(0);
        c.execute("DELETE FROM mdm_policies", &[]).await?;
        Ok(Fx {
            a,
            b,
            role,
            a_domain,
            b_domain,
            saved,
        })
    }

    /// The device, lockdown and policy rows a case starts from.
    pub async fn seed(&self, c: &Client, action: &str, label: &str) -> Result<(), BoxError> {
        let (a, b) = (self.a.user, self.b.user);
        // MDM device state: D1 clean, D2 other domain with a pending device wipe,
        // D3 executed, D4 in grace; check-in order D1 > D4 > D3 > D2.
        let state = |id: &str, user: i64, platform: &str, hours: i32, status: &str, extra: &str| {
            format!(
                "INSERT INTO mdm_device_state(device_id,user_id,platform,device_name,os_version,app_version,passcode_set,passcode_compliant,encryption_enabled,compliance_status,last_checkin_at,created_at,updated_at{}) VALUES('{id}',{user},'{platform}','dev-{}','17.2','1.4',true,true,true,'{status}',now()-interval '{hours} hours',now()-interval '30 days',now()-interval '1 day'{})",
                if extra.is_empty() { String::new() } else { format!(",{}", extra.split_once('|').unwrap().0) },
                &id[id.len() - 4..],
                if extra.is_empty() { String::new() } else { format!(",{}", extra.split_once('|').unwrap().1) },
            )
        };
        let mut sql = String::new();
        let d1_extra = match (action, label) {
            ("mdm-wipe", "conflict-level") => "wipe_requested,wipe_level,wipe_requested_at|'pending','account',now()-interval '1 hour'",
            ("mdm-wipe", "repeat") => "",
            _ => "",
        };
        sql.push_str(&state(D1, a, "ios", 1, "compliant", d1_extra));
        sql.push(';');
        sql.push_str(&state(D2, b, "android", 4, "non_compliant", "non_compliance_reasons,wipe_requested,wipe_level,wipe_requested_at|ARRAY['passcode <weak>','jailbreak & root'],'pending','device',now()-interval '2 hours'"));
        sql.push(';');
        let d3 = if (action, label) == ("mdm-wipe", "executed") {
            "wipe_requested,wipe_level,wipe_requested_at,wipe_acked_at|'executed','account',now()-interval '5 hours',now()-interval '4 hours'"
        } else {
            "wipe_requested,wipe_level,wipe_requested_at,wipe_acked_at|'executed','account',now()-interval '5 hours',now()-interval '4 hours'"
        };
        sql.push_str(&state(D3, a, "ios", 3, "compliant", d3));
        sql.push(';');
        sql.push_str(&state(
            D4,
            a,
            "android",
            2,
            "grace",
            "grace_until|now()+interval '2 days'",
        ));
        sql.push(';');
        c.batch_execute(&sql).await?;
        // Lockdown devices.
        let dev = |id: i64, user: i64, name: &str, platform: &str, state: &str, extra: &str| {
            let (cols, vals) = extra.split_once('|').unwrap_or(("", ""));
            format!(
                "INSERT INTO devices(id,user_id,device_name,platform,fingerprint,hmac_secret,enroll_state,created_at,updated_at{}{cols}) VALUES({id},{user},'{name}','{platform}','fp-{id}','seed-secret','{state}',now()-interval '10 days',now()-interval '1 day'{}{vals})",
                if cols.is_empty() { "" } else { "," },
                if cols.is_empty() { "" } else { "," },
            )
        };
        let mut sql = String::new();
        sql.push_str(&dev(
            L1,
            a,
            "laptop",
            "macos",
            "enrolled",
            &format!("enrolled_by|{a}"),
        ));
        sql.push(';');
        sql.push_str(&dev(
            L2,
            b,
            "phone <p>",
            "ios",
            "approved",
            &format!("enrolled_by,approved_by,approved_at|{a},{a},now()-interval '1 day'"),
        ));
        sql.push(';');
        sql.push_str(&dev(L3, a, "tablet", "android", "unenrolled", ""));
        sql.push(';');
        sql.push_str(&dev(
            L4,
            b,
            "old",
            "windows",
            "revoked",
            "revoked_at|now()-interval '2 days'",
        ));
        sql.push(';');
        let ev = |dev: i64, actor: &str, from: &str, to: &str, reason: &str, hours: i32| {
            format!("INSERT INTO device_enroll_events(device_id,actor_user_id,from_state,to_state,reason,created_at) VALUES({dev},{actor},'{from}','{to}','{reason}',now()-interval '{hours} hours');")
        };
        sql.push_str(&ev(
            L1,
            &a.to_string(),
            "unenrolled",
            "enrolled",
            "first",
            30,
        ));
        sql.push_str(&ev(
            L2,
            &a.to_string(),
            "unenrolled",
            "enrolled",
            "wave",
            50,
        ));
        sql.push_str(&ev(L2, &a.to_string(), "enrolled", "approved", "ok", 40));
        sql.push_str(&ev(L4, "NULL", "approved", "revoked", "lost", 60));
        c.batch_execute(&sql).await?;
        // Policies: two enabled globals and a disabled group policy.
        let p = |id: i64, name: &str, prio: i32, scope: &str, scope_id: &str, enabled: bool| {
            format!("INSERT INTO mdm_policies(id,name,description,priority,scope_type,scope_id,enabled) VALUES({id},'{name}','d-{id}',{prio},'{scope}',{scope_id},{enabled});")
        };
        let mut sql = String::new();
        match (action, label) {
            ("policies", "empty") => {}
            ("policy-delete", "last-global") => {
                sql.push_str(&p(P1, "Baseline", 10, "global", "NULL", true))
            }
            ("policy-delete", "disabled-global") => {
                sql.push_str(&p(P1, "Baseline", 10, "global", "NULL", false))
            }
            _ => {
                sql.push_str(&p(P1, "Baseline", 10, "global", "NULL", true));
                sql.push_str(&p(P2, "Executive <&> \"team\"", 20, "global", "NULL", true));
                sql.push_str(&p(P3, "Contractors", 30, "group", "5", false));
            }
        }
        sql.push_str(&format!(
            "SELECT setval(pg_get_serial_sequence('mdm_policies','id'),{NEXT_POLICY},false);"
        ));
        c.batch_execute(&sql).await?;
        Ok(())
    }

    pub async fn remove(&self, c: &Client) -> Result<(), BoxError> {
        clear_fixed(c).await?;
        c.execute("DELETE FROM mdm_policies", &[]).await?;
        c.execute(
            "INSERT INTO mdm_policies SELECT * FROM jsonb_populate_recordset(NULL::mdm_policies, $1::text::jsonb)",
            &[&self.saved],
        )
        .await?;
        c.execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&self.role],
        )
        .await?;
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&self.role])
            .await?;
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }

    /// Ids a case may mention, keyed by the JSON key that carries them.
    pub fn ids(&self) -> Vec<(&'static str, i64, String)> {
        let mut out: Vec<(&'static str, i64, String)> = vec![];
        for key in [
            "user_id",
            "actor_id",
            "actor_user_id",
            "enrolled_by",
            "approved_by",
            "owner_user_id",
            "armed_by",
            "updated_by",
            "created_by",
        ] {
            out.push((key, self.a.user, "<admin>".into()));
            out.push((key, self.b.user, "<other>".into()));
        }
        out.push(("domain_scope", self.a.domain, "<domain-a>".into()));
        out.push(("domain_scope", self.b.domain, "<domain-b>".into()));
        out
    }

    /// Domain names carry a per-run suffix.
    pub fn names(&self, text: &str) -> String {
        text.replace(&self.a_domain, "host-a.test")
            .replace(&self.b_domain, "host-b.test")
    }
}

/// Remove every fixed-id row a case (or an aborted one) may have left.
async fn clear_fixed(c: &Client) -> Result<(), BoxError> {
    let uuids: Vec<String> = UUIDS.iter().map(|s| s.to_string()).collect();
    c.execute(
        "DELETE FROM mdm_device_state WHERE device_id::text=ANY($1)",
        &[&uuids],
    )
    .await?;
    c.execute(
        "DELETE FROM device_events WHERE details->>'mdm_device_id'=ANY($1)",
        &[&uuids],
    )
    .await?;
    let ls: Vec<i64> = LS.to_vec();
    c.execute("DELETE FROM device_events WHERE device_id=ANY($1)", &[&ls])
        .await?;
    c.execute(
        "DELETE FROM device_enroll_events WHERE device_id=ANY($1)",
        &[&ls],
    )
    .await?;
    c.execute("DELETE FROM devices WHERE id=ANY($1)", &[&ls])
        .await?;
    Ok(())
}

fn base(method: &'static str, pattern: &'static str, path: String) -> Plan {
    Plan {
        method,
        pattern,
        path,
        query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        repeat: false,
        head: false,
    }
}
fn with_body(method: &'static str, pattern: &'static str, path: &str, body: &str) -> Plan {
    Plan {
        body: body.to_owned(),
        recorded_body: body.to_owned(),
        ..base(method, pattern, path.to_owned())
    }
}

const MDM_DEVICES: &str = "/admin/mdm/devices";
const MDM_DEVICE: &str = "/admin/mdm/devices/{device_id}";
const MDM_WIPE: &str = "/admin/mdm/devices/{device_id}/wipe";
const POLICIES: &str = "/admin/mdm/policies";
const POLICY: &str = "/admin/mdm/policies/{id}";
const REORDER: &str = "/admin/mdm/policies/reorder";
const QUEUE: &str = "/admin/devices/queue";
const DEVICES: &str = "/admin/devices";
const TRANSITION: &str = "/admin/devices/{id}/{action}";

/// The request of an (action, label) case.
pub fn plan(action: &str, label: &str, fx: &Fx) -> Plan {
    if matches!(
        action,
        "policy-delete" | "policy-create" | "policy-update" | "policy-reorder"
    ) && label == "repeat"
    {
        return Plan {
            repeat: true,
            ..plan(action, "success", fx)
        };
    }
    // `rls` cases send the success request under the row-security role.
    let label = if label == "rls" && action != "transition" {
        "success"
    } else {
        label
    };
    let guarded = matches!(label, "foreign" | "denied" | "wrong-perm");
    match action {
        "mdm-devices" => {
            let mut p = base("GET", MDM_DEVICES, MDM_DEVICES.to_owned());
            p.head = label == "head";
            if label == "ignored-query" {
                p.query = "?status=nosuch&platform=zzz&user_id=abc".into();
            }
            p
        }
        "mdm-device" => {
            let (id, head) = match label {
                "pending" | "foreign" => (D2.to_owned(), false),
                "executed" => (D3.to_owned(), false),
                "grace" => (D4.to_owned(), false),
                "reasons" => (D2.to_owned(), false),
                "missing" => ("00000000-0000-4000-8000-0000000000ff".to_owned(), false),
                "invalid" => ("not-a-uuid".to_owned(), false),
                "upper" => (D1.to_uppercase(), false),
                "braced" => (format!("%7B{D1}%7D"), false),
                "urn" => (format!("urn:uuid:{D1}"), false),
                "compact" => (D1.replace('-', ""), false),
                "head" => (D1.to_owned(), true),
                _ => (D1.to_owned(), false),
            };
            let mut p = base("GET", MDM_DEVICE, format!("/admin/mdm/devices/{id}"));
            p.head = head;
            p
        }
        "mdm-wipe" => {
            let path = |id: &str| format!("/admin/mdm/devices/{id}/wipe");
            match label {
                "success" | "foreign-own" | "denied" | "wrong-perm" => {
                    with_body("POST", MDM_WIPE, &path(D1), r#"{"level":"account"}"#)
                }
                "foreign" => with_body("POST", MDM_WIPE, &path(D2), r#"{"level":"account"}"#),
                "device-level" => with_body("POST", MDM_WIPE, &path(D1), r#"{"level":"device"}"#),
                "repeat" => Plan { repeat: true, ..with_body("POST", MDM_WIPE, &path(D1), r#"{"level":"account"}"#) },
                "conflict-level" => with_body("POST", MDM_WIPE, &path(D1), r#"{"level":"device"}"#),
                "executed" => with_body("POST", MDM_WIPE, &path(D3), r#"{"level":"account"}"#),
                "missing" => with_body("POST", MDM_WIPE, &path("00000000-0000-4000-8000-0000000000ff"), r#"{"level":"account"}"#),
                "invalid" => with_body("POST", MDM_WIPE, &path("nope"), r#"{"level":"account"}"#),
                "bad-json" => with_body("POST", MDM_WIPE, &path(D1), r#"{"level":"#),
                "empty-body" => with_body("POST", MDM_WIPE, &path(D1), ""),
                "null-body" => with_body("POST", MDM_WIPE, &path(D1), "null"),
                "bad-level" => with_body("POST", MDM_WIPE, &path(D1), r#"{"level":"nuke"}"#),
                "typed" => with_body("POST", MDM_WIPE, &path(D1), r#"{"level":5}"#),
                "case-key" => with_body("POST", MDM_WIPE, &path(D1), r#"{"LEVEL":"device"}"#),
                "unknown-keys" => with_body("POST", MDM_WIPE, &path(D1), r#"{"extra":1,"level":"account","x":[1]}"#),
                "trailing" => with_body("POST", MDM_WIPE, &path(D1), r#"{"level":"account"} junk"#),
                _ => unreachable!("{label}"),
            }
        }
        "policies" => {
            let mut p = base("GET", POLICIES, POLICIES.to_owned());
            p.head = label == "head";
            p
        }
        "policy-create" => {
            let b = |body: &str| with_body("POST", POLICIES, POLICIES, body);
            match label {
                "success" | "foreign" | "denied" | "wrong-perm" => b(r#"{"name":"New policy"}"#),
                "full" => b(r#"{"name":"Full","description":"every field","priority":7,"scope_type":"group","scope_id":42,"enabled":false,"passcode_min_length":8,"passcode_complexity":"complex","passcode_max_age_days":30,"passcode_history_count":3,"max_failed_attempts":4,"inactivity_lock_mins":2,"block_screenshots":true,"block_copy_paste":true,"require_device_encryption":false,"min_os_version_ios":"16.0","min_os_version_android":"13","jailbreak_action":"block","heartbeat_interval_secs":600,"grace_period_mins":15}"#),
                "implicit" => b(r#"{"name":"Defaults","enabled":null,"priority":null}"#),
                "html" => b(r#"{"name":"A <b>&</b> é ","description":"line\nbreak"}"#),
                "no-name" => b(r#"{"description":"nameless"}"#),
                "empty-name" => b(r#"{"name":""}"#),
                "bad-scope" => b(r#"{"name":"x","scope_type":"galaxy"}"#),
                "bad-complexity" => b(r#"{"name":"x","passcode_complexity":"hard"}"#),
                "bad-jailbreak" => b(r#"{"name":"x","jailbreak_action":"ignore"}"#),
                "negative-length" => b(r#"{"name":"x","passcode_min_length":-1}"#),
                "bad-json" => b(r#"{"name":"x",}"#),
                "eof" => b(""),
                "typed-int" => b(r#"{"name":"x","priority":"high"}"#),
                "float-int" => b(r#"{"name":"x","priority":1.5}"#),
                "typed-bool" => b(r#"{"name":"x","enabled":"yes"}"#),
                "typed-scope-id" => b(r#"{"name":"x","scope_id":true}"#),
                "overflow" => b(r#"{"name":"x","priority":3000000000}"#),
                "check-fail" => b(r#"{"name":"x","passcode_complexity":"none","jailbreak_action":"none","scope_type":"user","heartbeat_interval_secs":-5,"grace_period_mins":99999999999}"#),
                "null-body" => b("null"),
                "array-body" => b("[1,2]"),
                "case-keys" => b(r#"{"NAME":"Folded","Priority":3,"ENABLED":false}"#),
                "unknown-keys" => b(r#"{"name":"x","bogus":{"a":1},"id":5}"#),
                "trailing" => b(r#"{"name":"x"} trailing"#),
                _ => unreachable!("{label}"),
            }
        }
        "policy-update" => {
            let path = |id: &str| format!("/admin/mdm/policies/{id}");
            let b = |id: &str, body: &str| with_body("PUT", POLICY, &path(id), body);
            let p1 = P1.to_string();
            match label {
                "success" | "foreign" | "denied" | "wrong-perm" => b(&p1, r#"{"name":"Renamed","priority":99,"scope_id":7}"#),
                "full" => b(&P2.to_string(), r#"{"name":"Full","description":"every field","priority":7,"scope_type":"user","scope_id":42,"enabled":false,"passcode_min_length":8,"passcode_complexity":"complex","passcode_max_age_days":30,"passcode_history_count":3,"max_failed_attempts":4,"inactivity_lock_mins":2,"block_screenshots":true,"block_copy_paste":true,"require_device_encryption":false,"min_os_version_ios":"16.0","min_os_version_android":"13","jailbreak_action":"block","heartbeat_interval_secs":600,"grace_period_mins":15}"#),
                "scope-reset" => b(&P3.to_string(), r#"{"description":"scope id dropped"}"#),
                "missing" => b(&MISSING.to_string(), r#"{"name":"x"}"#),
                "invalid" => b("abc", r#"{"name":"x"}"#),
                "plus-id" => b(&format!("%2B{P1}"), r#"{"name":"Plus"}"#),
                "empty-name" => b(&p1, r#"{"name":""}"#),
                "bad-scope" => b(&p1, r#"{"scope_type":"galaxy"}"#),
                "bad-json" => b(&p1, r#"{"name":"#),
                "typed" => b(&p1, r#"{"enabled":"no"}"#),
                "empty-object" => b(&p1, "{}"),
                "overflow" => b(&p1, r#"{"priority":3000000000}"#),
                "check-fail" => b(&p1, r#"{"scope_type":"user","passcode_min_length":99999999999}"#),
                _ => unreachable!("{label}"),
            }
        }
        "policy-delete" => {
            let id = match label {
                "missing" => MISSING.to_string(),
                "invalid" => "abc".into(),
                "last-global" | "disabled-global" => P1.to_string(),
                _ => P2.to_string(),
            };
            base("DELETE", POLICY, format!("/admin/mdm/policies/{id}"))
        }
        "policy-reorder" => {
            let b = |body: &str| with_body("PUT", REORDER, REORDER, body);
            match label {
                "success" | "foreign" | "denied" | "wrong-perm" => b(&format!(r#"{{"ids":[{P3},{P1},{P2}]}}"#)),
                "single" => b(&format!(r#"{{"ids":[{P2}]}}"#)),
                "repeat-ids" => b(&format!(r#"{{"ids":[{P1},{P2},{P1}]}}"#)),
                "unknown-ids" => b(&format!(r#"{{"ids":[{MISSING},{P2},0,-1]}}"#)),
                "empty-list" => b(r#"{"ids":[]}"#),
                "no-ids" => b("{}"),
                "bad-json" => b(r#"{"ids":[1,"#),
                "typed-id" => b(&format!(r#"{{"ids":[{P1},"x"]}}"#)),
                "float-id" => b(&format!(r#"{{"ids":[{P1},1.5]}}"#)),
                "null-id" => b(&format!(r#"{{"ids":[{P1},null]}}"#)),
                "null-ids" => b(r#"{"ids":null}"#),
                "not-array" => b(r#"{"ids":"x"}"#),
                _ => unreachable!("{label}"),
            }
        }
        "queue" => {
            let mut p = base("GET", QUEUE, QUEUE.to_owned());
            p.query = match label {
                "approved" | "foreign-target" => "?state=approved".into(),
                "revoked" => "?state=revoked".into(),
                "unenrolled" => "?state=unenrolled".into(),
                "q-email" => format!("?state=approved&q={}", "dev1-admin"),
                "q-name" => "?state=approved&q=dev1-other".into(),
                "q-wild" => "?state=approved&q=%25".into(),
                "limit" => "?state=approved&limit=1".into(),
                "limit-bad" => "?state=approved&limit=abc".into(),
                "limit-negative" => "?state=approved&limit=-3".into(),
                "limit-big" => "?state=approved&limit=100000".into(),
                "empty" => "?state=nosuch".into(),
                _ => String::new(),
            };
            p.head = label == "head";
            p
        }
        "devices-list" => {
            let mut p = base("GET", DEVICES, DEVICES.to_owned());
            p.query = match label {
                "other-user" | "foreign-target" => format!("?user_id={}", fx.b.user),
                "no-user" => String::new(),
                "invalid" => "?user_id=abc".into(),
                "zero" => "?user_id=0".into(),
                "negative" => "?user_id=-4".into(),
                "missing" => format!("?user_id={MISSING}"),
                _ => format!("?user_id={}", fx.a.user),
            };
            p.head = label == "head";
            p
        }
        "transition" => {
            let path = |id: i64, a: &str| format!("/admin/devices/{id}/{a}");
            let b = |id: i64, a: &str, body: &str| with_body("POST", TRANSITION, &path(id, a), body);
            match label {
                "success" | "foreign" | "denied" | "wrong-perm" => b(L1, "approve", r#"{"reason":"looks fine"}"#),
                "enroll" => b(L3, "enroll", r#"{"reason":"onboarding"}"#),
                "rls" => b(L2, "revoke", r#"{"reason":"row security"}"#),
                "rls-own" => b(L1, "approve", r#"{"reason":"own device row security"}"#),
                "foreign-target" => b(L2, "revoke", r#"{"reason":"other domain device"}"#),
                "revoke" => b(L2, "revoke", r#"{"reason":"lost <phone> & stolen"}"#),
                "revoke-enrolled" => b(L1, "revoke", ""),
                "illegal" => b(L2, "enroll", r#"{"reason":"again"}"#),
                "missing" => b(MISSING, "approve", "{}"),
                "unknown-action" => b(L1, "promote", "{}"),
                "invalid-id" => with_body("POST", TRANSITION, "/admin/devices/abc/approve", "{}"),
                "reason" => b(L1, "approve", r#"{"REASON":"folded","extra":[1]}"#),
                "no-body" => b(L1, "approve", ""),
                "bad-json" => b(L1, "approve", r#"{"reason":"#),
                "reason-typed" => b(L1, "approve", r#"{"reason":5}"#),
                "zero-id" => b(0, "approve", "{}"),
                "repeat" => Plan { repeat: true, ..b(L1, "approve", r#"{"reason":"first"}"#) },
                _ => unreachable!("{label}"),
            }
        }
        _ => unreachable!("{action}"),
    }
    .tap(guarded)
}

trait Tap: Sized {
    fn tap(self, _guarded: bool) -> Self {
        self
    }
}
impl Tap for Plan {}
