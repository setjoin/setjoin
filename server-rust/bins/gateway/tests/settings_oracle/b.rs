//! Slice `settings-b` (#307): notification preferences, VIP senders, automatic replies and
//! approval delegation (GET and PUT each) plus `PUT /user/offline/sync-preferences`.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

/// `(method, inventory pattern)` for an action.
pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "notif-get" => ("GET", "/user/notification-preferences"),
        "notif-put" => ("PUT", "/user/notification-preferences"),
        "vip-get" => ("GET", "/user/vip-senders"),
        "vip-put" => ("PUT", "/user/vip-senders"),
        "vacation-get" => ("GET", "/user/automatic-replies"),
        "vacation-put" => ("PUT", "/user/automatic-replies"),
        "delegation-get" => ("GET", "/user/approval-delegation"),
        "delegation-put" => ("PUT", "/user/approval-delegation"),
        "sync-put" => ("PUT", "/user/offline/sync-preferences"),
        _ => panic!("unknown settings-b action {action}"),
    }
}

/// The status Go answers; `None` leaves the recorded status unchecked.
pub fn wanted(action: &str, label: &str) -> Option<u16> {
    match (action, label) {
        (_, "bad-json" | "wrong-type" | "array-body" | "float-id") => Some(400),
        ("notif-put", "bad-fp" | "bad-policy" | "bad-chat" | "fp-short" | "fp-int") => Some(400),
        ("vip-put", "empty" | "blank" | "nbsp") => Some(400),
        // Go calls the reducer without the user GUC: FORCE-RLS refuses every add (Go bug, mirrored).
        ("vip-put", "off" | "off-missing" | "missing-vip" | "shared" | "repeat") => Some(200),
        ("vip-put", _) => Some(500),
        ("vacation-put", "bad-audience" | "bad-order") => Some(400),
        (
            "delegation-put",
            "self" | "cross-domain" | "missing-user" | "bad-range" | "equal-range" | "no-times",
        ) => Some(400),
        (
            "sync-put",
            "toggle-off" | "connectivity-off" | "no-device-claim" | "unregistered" | "foreign"
            | "mode-off" | "no-policy",
        ) => Some(404),
        (
            "sync-put",
            "unknown-field" | "trailing" | "negative-window" | "bad-network" | "bad-prefetch"
            | "empty-body" | "too-big" | "float-window" | "missing" | "null-body",
        ) => Some(400),
        // Go: the reducer runs without the user GUC, so the UPDATE finds no row (BZ100, Go bug).
        ("sync-put", "success" | "clamp" | "opt-out" | "fold" | "repeat") => Some(409),
        ("sync-put", "int-overflow") => Some(500),
        ("notif-put", "bad-dnd" | "dnd-days-overflow" | "bad-mail" | "null-body") => Some(500),
        ("vacation-put", "bad-date" | "empty-date" | "nul") => Some(500),
        ("delegation-put", "bad-time") => Some(500),
        (_, _) if action.ends_with("-get") => None,
        _ => Some(200),
    }
}

const G1: &str = "11111111-1111-4111-8111-111111111111";
const G2: &str = "22222222-2222-4222-8222-222222222222";

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    let mut extra_users = vec![];
    let foreign = label == "foreign";
    // ---- notification preferences ----
    let insert = "INSERT INTO user_notification_prefs(user_id,device_fingerprint,push_enabled,push_sound,stop_push_when_desktop_online,dnd_start,dnd_end,dnd_days,mail_notifications,calendar_reminders,task_reminders,read_receipt_policy,chat_notifications,created_at,updated_at) VALUES($1,$2::text::uuid,$3,$4,$5,$6::text::time,$7::text::time,$8,$9,$10,$11,$12,$13,'2026-10-01T10:00:00Z','2026-10-01T10:00:00Z')";
    for (user, mine) in [(a.user, true), (b.user, false)] {
        if mine && foreign {
            continue;
        }
        let none: Option<&str> = None;
        owner
            .execute(
                insert,
                &[
                    &user, &none, &true, &"default", &false, &none, &none, &127_i16, &"all", &true,
                    &true, &"ask", &"all",
                ],
            )
            .await?;
        owner
            .execute(
                insert,
                &[
                    &user,
                    &Some(G1),
                    &true,
                    &"chime",
                    &true,
                    &Some("22:00"),
                    &Some("07:30:15"),
                    &62_i16,
                    &"important",
                    &false,
                    &true,
                    &"always",
                    &"mentions",
                ],
            )
            .await?;
    }
    if label == "null-cols" {
        owner
            .execute(
                "INSERT INTO user_notification_prefs(user_id,device_fingerprint,push_enabled,push_sound,created_at,updated_at) VALUES($1,$2::text::uuid,NULL,NULL,'2026-10-01T10:00:00Z','2026-10-01T10:00:00Z')",
                &[&a.user, &G2],
            )
            .await?;
    }
    // ---- VIP senders ----
    let vip = "INSERT INTO vip_senders(user_id,sender_email,created_at) VALUES($1,$2,$3::text::timestamptz)";
    if !foreign && label != "empty-list" {
        owner
            .execute(vip, &[&a.user, &"zed@vip.test", &"2026-10-01T10:00:01Z"])
            .await?;
        owner
            .execute(vip, &[&a.user, &"amy@vip.test", &"2026-10-01T10:00:02Z"])
            .await?;
    }
    owner
        .execute(vip, &[&b.user, &"amy@vip.test", &"2026-10-01T10:00:03Z"])
        .await?;
    owner
        .execute(vip, &[&b.user, &"other@vip.test", &"2026-10-01T10:00:04Z"])
        .await?;
    // ---- automatic replies ----
    let vac = "INSERT INTO vacation_settings(mailbox_id,enabled,subject,body_text,body_html,body_external,body_external_html,start_date,end_date,external_audience,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::text::date,$9::text::date,$10,'2026-10-01T10:00:00Z')";
    if !foreign {
        let html: Option<&str> = if label == "null-html" {
            None
        } else {
            Some("<p>Back & soon</p>")
        };
        let (start, end): (Option<&str>, Option<&str>) = if label == "no-dates" {
            (None, None)
        } else {
            (Some("2026-10-05"), Some("2026-10-12"))
        };
        owner
            .execute(
                vac,
                &[
                    &a.mailbox,
                    &true,
                    &"Away <now>",
                    &"Back soon",
                    &html,
                    &html.map(|_| "External text"),
                    &html.map(|_| "<i>ext</i>"),
                    &start,
                    &end,
                    &"contacts",
                ],
            )
            .await?;
    }
    owner
        .execute(
            vac,
            &[
                &b.mailbox,
                &true,
                &"Other away",
                &"Other body",
                &Some("<p>o</p>"),
                &None::<&str>,
                &None::<&str>,
                &Some("2026-10-06"),
                &Some("2026-10-09"),
                &"all",
            ],
        )
        .await?;
    // ---- approval delegation ----
    let delegate: i64 = owner
        .query_one(
            "INSERT INTO users (username, domain_id, email, display_name, password_hash) \
             SELECT 'delegate@'||d.name, d.id, 'delegate@'||d.name, 'Delegate <C>', 'x' FROM domains d WHERE d.id=$1 RETURNING id",
            &[&a.domain],
        )
        .await?
        .get(0);
    extra_users.push(delegate);
    vars.insert("delegate", delegate);
    vars.insert("actor", a.user);
    vars.insert("other", b.user);
    names.push(("delegate_user_id", delegate, "<delegate>".into()));
    names.push(("delegate_user_id", b.user, "<other>".into()));
    if !foreign {
        owner
            .execute(
                "INSERT INTO approval_delegations(delegator_user_id,delegate_user_id,starts_at,ends_at,created_at) VALUES($1,$2,'2026-10-05T09:00:00Z','2026-10-12T17:30:00Z','2026-10-01T10:00:00Z')",
                &[&a.user, &delegate],
            )
            .await?;
    }
    owner
        .execute(
            "INSERT INTO approval_delegations(delegator_user_id,delegate_user_id,starts_at,ends_at,created_at) VALUES($1,$2,'2026-10-06T09:00:00Z','2026-10-08T17:30:00Z','2026-10-01T10:00:00Z')",
            &[&b.user, &delegate],
        )
        .await?;
    let mut undo = vec![];
    let mut text_masks = vec![];
    if action == "sync-put" {
        vars.insert("sync", 1);
        let rows = owner
            .query(
                "SELECT key, enabled FROM feature_toggles WHERE key = ANY($1)",
                &[&vec![
                    "feature.offline_mail",
                    "feature.connectivity_aware_sync",
                ]],
            )
            .await?;
        for row in &rows {
            let (key, was): (String, bool) = (row.get(0), row.get(1));
            undo.push(format!(
                "UPDATE feature_toggles SET enabled = {was} WHERE key = '{key}'"
            ));
        }
        let on = |key: &str| match (key, label) {
            ("feature.offline_mail", "toggle-off") => false,
            ("feature.connectivity_aware_sync", "connectivity-off") => false,
            _ => true,
        };
        for key in ["feature.offline_mail", "feature.connectivity_aware_sync"] {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled = $2 WHERE key = $1",
                    &[&key, &on(key)],
                )
                .await?;
        }
        for (user, fp, mine) in [(a.user, ACTOR_DEVICE, true), (b.user, OTHER_DEVICE, false)] {
            if mine && matches!(label, "foreign" | "unregistered") {
                continue;
            }
            let device: i64 = owner.query_one("INSERT INTO user_devices(user_id,device_name,platform,fingerprint_hash,offline_approval,offline_opt_in,offline_window_days,background_sync_enabled,automatic_network_pref,attachment_prefetch_pref) VALUES($1,$2,'desktop',sha256(convert_to($3,'UTF8')),'approved',TRUE,7,TRUE,'unmetered','never') RETURNING id", &[&user, &"settings2 device", &fp]).await?.get(0);
            if mine {
                text_masks.push((
                    format!("device {device} not found"),
                    "device <device> not found".into(),
                ));
            }
        }
        if label != "no-policy" {
            let mode = if label == "mode-off" {
                "off"
            } else {
                "execute"
            };
            owner.execute("INSERT INTO offline_policies(name,scope_type,scope_id,enabled,max_offline_days,require_approval,priority,background_sync_allowed,automatic_network_max,attachment_prefetch_max,connectivity_sync_mode) VALUES('settings2-user','user',$1,TRUE,14,FALSE,5,TRUE,'any','always',$2)", &[&a.user, &mode]).await?;
            undo.push(format!(
                "DELETE FROM offline_policies WHERE name='settings2-user' AND scope_id={}",
                a.user
            ));
        }
    }
    Ok(Seed {
        names,
        vars,
        extra_users,
        undo,
        text_masks,
    })
}

const ACTOR_DEVICE: &str = "gofree-settings2-actor-device";
const OTHER_DEVICE: &str = "gofree-settings2-other-device";

/// The actor's access token; sync cases carry the device claim Go reads.
pub fn token(action: &str, label: &str, user: i64) -> String {
    if action != "sync-put" || label == "no-device-claim" {
        return crate::common::recovery_token(user);
    }
    let fp = match label {
        "foreign" => OTHER_DEVICE,
        "unregistered" => "gofree-settings2-unknown-device",
        _ => ACTOR_DEVICE,
    };
    crate::common::recovery_token_with(
        user,
        json!({"device":{"id":fp,"platform":"desktop","trust_tier":"trusted","compliance_status":"ok","wipe_requested":false}}),
    )
}

fn long(n: usize) -> String {
    "x".repeat(n)
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let var = |k: &str| seed.vars.get(k).copied().unwrap_or(0);
    let query = if label == "ignored-query" {
        "?limit=-1&x=%zz"
    } else {
        ""
    };
    // The recorded body names ids symbolically so goldens stay run independent.
    let mut recorded = None;
    let prefs = |extra: &str| {
        format!(
            r#"{{"push_enabled":false,"push_sound":"ping","stop_push_when_desktop_online":true,"dnd_start":"21:30","dnd_end":"06:45","dnd_days":31,"mail_notifications":"off","calendar_reminders":false,"task_reminders":false,"read_receipt_policy":"never","chat_notifications":"off"{extra}}}"#
        )
    };
    let notif = |fp: &str, p: &str| format!(r#"{{"device_fingerprint":{fp},"preferences":{p}}}"#);
    let global = prefs("");
    let body = match (action, label) {
        (_, "bad-json") => "{".to_owned(),
        (_, "array-body") => "[1]".to_owned(),
        ("notif-put", "wrong-type") => notif("null", r#"{"push_enabled":"yes"}"#),
        ("notif-put", "bad-fp") => notif(r#""not-a-uuid""#, &global),
        ("notif-put", "fp-short") => notif(r#""1111""#, &global),
        ("notif-put", "fp-empty") => notif(r#""""#, &global),
        ("notif-put", "fp-int") => notif("5", &global),
        ("notif-put", "device") => notif(&format!("\"{G2}\""), &global),
        ("notif-put", "device-update") => notif(&format!("\"{G1}\""), &global),
        ("notif-put", "fp-upper") => notif(&format!("\"{}\"", G1.replace('1', "A").replace('4', "B")), &global),
        ("notif-put", "fp-urn") => notif(&format!("\"urn:uuid:{G2}\""), &global),
        ("notif-put", "fp-braces") => notif(&format!("\"{{{G2}}}\""), &global),
        ("notif-put", "fp-plain") => notif(&format!("\"{}\"", G2.replace('-', "")), &global),
        ("notif-put", "bad-policy") => notif("null", &prefs(r#","read_receipt_policy":"sometimes""#)),
        ("notif-put", "bad-chat") => notif("null", &prefs(r#","chat_notifications":"loud""#)),
        ("notif-put", "policy-keep") => notif("null", r#"{"push_enabled":true,"push_sound":"default","dnd_days":127,"mail_notifications":"all","calendar_reminders":true,"task_reminders":true}"#),
        ("notif-put", "bad-dnd") => notif("null", &prefs(r#","dnd_start":"25:99""#)),
        ("notif-put", "dnd-days-overflow") => notif("null", &prefs(r#","dnd_days":70000"#)),
        ("notif-put", "bad-mail") => notif("null", &prefs(r#","mail_notifications":"sometimes""#)),
        ("notif-put", "null-body") => "null".to_owned(),
        ("notif-put", "no-dnd") => notif("null", r#"{"push_enabled":true,"push_sound":"s","dnd_days":3,"mail_notifications":"all","calendar_reminders":true,"task_reminders":true,"dnd_start":null}"#),
        ("notif-put", "fold") => notif("null", r#"{"PUSH_ENABLED":true,"Push_Sound":"<b>","DND_DAYS":9,"MAIL_NOTIFICATIONS":"important","unknown":[1,2],"calendar_reminders":null}"#),
        ("notif-put", "trailing") => format!("{} trailing", notif("null", &global)),
        ("notif-put", _) => notif("null", &global),
        ("vip-put", "empty") => r#"{"email":"","vip":true}"#.to_owned(),
        ("vip-put", "blank") => "{\"email\":\"  \\t \",\"vip\":true}".to_owned(),
        ("vip-put", "nbsp") => "{\"email\":\"\\u00a0\\u3000\",\"vip\":true}".to_owned(),
        ("vip-put", "wrong-type") => r#"{"email":"x@vip.test","vip":"yes"}"#.to_owned(),
        ("vip-put", "off" | "repeat") => r#"{"email":"zed@vip.test","vip":false}"#.to_owned(),
        ("vip-put", "off-missing") => r#"{"email":"nobody@vip.test","vip":false}"#.to_owned(),
        ("vip-put", "missing-vip") => r#"{"email":"zed@vip.test"}"#.to_owned(),
        ("vip-put", "shared") => r#"{"email":"amy@vip.test","vip":false}"#.to_owned(),
        ("vip-put", "case") => "{\"email\":\"  New.User@VIP.Test \\u00a0\",\"vip\":true}".to_owned(),
        ("vip-put", "unicode") => r#"{"email":"ÄÖ@vip.test","vip":true}"#.to_owned(),
        ("vip-put", "existing") => r#"{"email":"AMY@vip.test","vip":true}"#.to_owned(),
        ("vip-put", "fold") => r#"{"EMAIL":"fold@vip.test","VIP":true}"#.to_owned(),
        ("vip-put", _) => r#"{"email":"new@vip.test","vip":true}"#.to_owned(),
        ("vacation-put", "bad-audience") => r#"{"external_audience":"everyone"}"#.to_owned(),
        ("vacation-put", "empty-audience") => r#"{"enabled":true,"subject":"S","external_audience":""}"#.to_owned(),
        ("vacation-put", "bad-order") => r#"{"enabled":true,"subject":"S","start_date":"2026-10-12","end_date":"2026-10-05"}"#.to_owned(),
        ("vacation-put", "bad-date") => r#"{"enabled":true,"subject":"S","start_date":"someday"}"#.to_owned(),
        ("vacation-put", "empty-date") => r#"{"enabled":true,"subject":"S","start_date":""}"#.to_owned(),
        ("vacation-put", "wrong-type") => r#"{"enabled":"yes"}"#.to_owned(),
        ("vacation-put", "null-body") => "null".to_owned(),
        ("vacation-put", "disable") => r#"{"enabled":false,"subject":"Back","body_internal":"in","external_audience":"none"}"#.to_owned(),
        ("vacation-put", "clear-dates") => r#"{"enabled":true,"subject":"S","start_date":null,"end_date":null}"#.to_owned(),
        ("vacation-put", "loose-date") => r#"{"enabled":true,"subject":"S","start_date":"Oct 7 2026","end_date":"2026-10-09 23:00"}"#.to_owned(),
        ("vacation-put", "html") => r#"{"enabled":true,"subject":"<S> & é","body_internal":"in <b>","body_internal_html":"<p>in</p>","body_external":"ex","body_external_html":"<p>ex</p>","external_audience":"all"}"#.to_owned(),
        ("vacation-put", "fold") => r#"{"ENABLED":true,"Subject":"Folded","BODY_INTERNAL":"b","unknown":{"a":1}}"#.to_owned(),
        ("vacation-put", "nul") => "{\"enabled\":true,\"subject\":\"a\\u0000b\"}".to_owned(),
        ("vacation-put", "long") => format!(r#"{{"enabled":true,"subject":"S","body_internal":"{}"}}"#, long(200_000)),
        ("vacation-put", _) => r#"{"enabled":true,"subject":"Out until Monday","body_internal":"Inside text","body_internal_html":"<p>Inside</p>","body_external":"Outside text","body_external_html":"<p>Outside</p>","start_date":"2026-11-02","end_date":"2026-11-09","external_audience":"contacts"}"#.to_owned(),
        ("sync-put", _) => {
            let ok = r#"{"optIn":true,"windowDays":10,"backgroundSyncEnabled":false,"automaticNetwork":"unmetered","attachmentPrefetch":"never"}"#;
            match label {
                "bad-json" => "{".into(),
                "array-body" => "[1]".into(),
                "empty-body" => String::new(),
                "unknown-field" => r#"{"optIn":true,"windowDays":1,"backgroundSyncEnabled":true,"automaticNetwork":"any","attachmentPrefetch":"always","extra":1}"#.into(),
                "trailing" => format!("{ok} {{}}"),
                "negative-window" => r#"{"optIn":true,"windowDays":-1,"backgroundSyncEnabled":true,"automaticNetwork":"any","attachmentPrefetch":"always"}"#.into(),
                "bad-network" => r#"{"optIn":true,"windowDays":1,"backgroundSyncEnabled":true,"automaticNetwork":"wifi","attachmentPrefetch":"always"}"#.into(),
                "bad-prefetch" => r#"{"optIn":true,"windowDays":1,"backgroundSyncEnabled":true,"automaticNetwork":"any","attachmentPrefetch":"sometimes"}"#.into(),
                "wrong-type" => r#"{"optIn":"yes","windowDays":1,"automaticNetwork":"any","attachmentPrefetch":"always"}"#.into(),
                "float-window" => r#"{"optIn":true,"windowDays":1.5,"automaticNetwork":"any","attachmentPrefetch":"always"}"#.into(),
                "missing" => r#"{"optIn":true}"#.into(),
                "too-big" => format!(r#"{{"optIn":true,"windowDays":1,"automaticNetwork":"any","attachmentPrefetch":"always","pad":"{}"}}"#, long(5000)),
                "clamp" => r#"{"optIn":true,"windowDays":100,"backgroundSyncEnabled":true,"automaticNetwork":"any","attachmentPrefetch":"always"}"#.into(),
                "int-overflow" => r#"{"optIn":true,"windowDays":3000000000,"backgroundSyncEnabled":true,"automaticNetwork":"any","attachmentPrefetch":"always"}"#.into(),
                "opt-out" => r#"{"optIn":false,"windowDays":0,"backgroundSyncEnabled":false,"automaticNetwork":"never","attachmentPrefetch":"never"}"#.into(),
                "fold" => r#"{"OPTIN":true,"WindowDays":3,"BACKGROUNDSYNCENABLED":true,"AutomaticNetwork":"any","attachmentprefetch":"unmetered","windowDays":null}"#.into(),
                "null-body" => "null".into(),
                _ => ok.to_owned(),
            }
        }
        ("delegation-put", label) => {
            let times = r#""starts_at":"2026-11-02T09:00","ends_at":"2026-11-09T17:30""#;
            let d = |id: String| format!(r#"{{"enabled":true,"delegate_user_id":{id},{times}}}"#);
            let shown = |text: &str| text.to_owned();
            let (body, shown_body) = match label {
                "self" => (d(var("actor").to_string()), shown(&d("\"<actor>\"".into()))),
                "cross-domain" => (d(var("other").to_string()), shown(&d("\"<other>\"".into()))),
                "missing-user" => (d("999999999".into()), shown(&d("999999999".into()))),
                "bad-range" => {
                    let b = format!(r#"{{"enabled":true,"delegate_user_id":{},"starts_at":"2026-11-09T09:00","ends_at":"2026-11-02T09:00"}}"#, var("delegate"));
                    (b, r#"{"enabled":true,"delegate_user_id":"<delegate>","starts_at":"2026-11-09T09:00","ends_at":"2026-11-02T09:00"}"#.into())
                }
                "equal-range" => {
                    let b = format!(r#"{{"enabled":true,"delegate_user_id":{},"starts_at":"2026-11-09T09:00","ends_at":"2026-11-09T09:00"}}"#, var("delegate"));
                    (b, r#"{"enabled":true,"delegate_user_id":"<delegate>","starts_at":"2026-11-09T09:00","ends_at":"2026-11-09T09:00"}"#.into())
                }
                "no-times" => {
                    let b = format!(r#"{{"enabled":true,"delegate_user_id":{}}}"#, var("delegate"));
                    (b, r#"{"enabled":true,"delegate_user_id":"<delegate>"}"#.into())
                }
                "bad-time" => {
                    let b = format!(r#"{{"enabled":true,"delegate_user_id":{},"starts_at":"soon","ends_at":"2026-11-09T09:00"}}"#, var("delegate"));
                    (b, r#"{"enabled":true,"delegate_user_id":"<delegate>","starts_at":"soon","ends_at":"2026-11-09T09:00"}"#.into())
                }
                "offset" => {
                    let b = format!(r#"{{"enabled":true,"delegate_user_id":{},"starts_at":"2026-11-02T09:00:00+02:00","ends_at":"2026-11-09 17:30:00Z"}}"#, var("delegate"));
                    (b, r#"{"enabled":true,"delegate_user_id":"<delegate>","starts_at":"2026-11-02T09:00:00+02:00","ends_at":"2026-11-09 17:30:00Z"}"#.into())
                }
                "clear" => (r#"{"enabled":false,"delegate_user_id":0}"#.into(), r#"{"enabled":false,"delegate_user_id":0}"#.into()),
                "disabled-with-delegate" => {
                    let b = format!(r#"{{"enabled":false,"delegate_user_id":{},{times}}}"#, var("delegate"));
                    (b, format!(r#"{{"enabled":false,"delegate_user_id":"<delegate>",{times}}}"#))
                }
                "zero-delegate" => (format!(r#"{{"enabled":true,"delegate_user_id":0,{times}}}"#), format!(r#"{{"enabled":true,"delegate_user_id":0,{times}}}"#)),
                "wrong-type" => (r#"{"enabled":true,"delegate_user_id":"7"}"#.into(), r#"{"enabled":true,"delegate_user_id":"7"}"#.into()),
                "float-id" => (r#"{"enabled":true,"delegate_user_id":1.5}"#.into(), r#"{"enabled":true,"delegate_user_id":1.5}"#.into()),
                "fold" => {
                    let b = format!(r#"{{"ENABLED":true,"Delegate_User_ID":{},"STARTS_AT":"2026-11-02T09:00","ends_at":"2026-11-09T17:30","delegate_name":"ignored","unknown":1}}"#, var("delegate"));
                    (b, r#"{"ENABLED":true,"Delegate_User_ID":"<delegate>","STARTS_AT":"2026-11-02T09:00","ends_at":"2026-11-09T17:30","delegate_name":"ignored","unknown":1}"#.into())
                }
                "null-body" => ("null".into(), "null".into()),
                "bad-json" | "array-body" => (String::new(), String::new()),
                _ => (d(var("delegate").to_string()), shown(&d("\"<delegate>\"".into()))),
            };
            if !body.is_empty() || label == "null-body" {
                recorded = Some(shown_body);
                body
            } else if label == "array-body" {
                "[1]".into()
            } else {
                "{".into()
            }
        }
        _ => String::new(),
    };
    let recorded_body = match (&recorded, action, label) {
        (_, "vacation-put", "long") => "<body_internal of 200000 bytes>".to_owned(),
        (Some(shown), _, _) => shown.clone(),
        _ => body.clone(),
    };
    Req {
        path: pattern.to_owned(),
        query: query.into(),
        recorded_body,
        body,
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    seed: &Seed,
) -> Result<Value, BoxError> {
    let devices = super::rows(owner, &format!("SELECT jsonb_build_object('who',CASE user_id WHEN {} THEN 'actor' ELSE 'other' END,'opt_in',offline_opt_in,'window_days',offline_window_days,'background',background_sync_enabled,'network',automatic_network_pref,'prefetch',attachment_prefetch_pref,'approval',offline_approval)::text FROM user_devices WHERE user_id IN ({},{}) ORDER BY user_id=0, id", a.user, a.user, b.user)).await?;
    let delegate = seed.vars.get("delegate").copied().unwrap_or(0);
    let mut out = serde_json::Map::new();
    let (mut notif, mut vip, mut vac, mut del) = (vec![], vec![], vec![], vec![]);
    for (account, who) in [(a, "actor"), (b, "other")] {
        let rows = super::rows(owner, &format!("SELECT jsonb_build_object('fp',device_fingerprint,'push_enabled',push_enabled,'push_sound',push_sound,'stop',stop_push_when_desktop_online,'dnd_start',dnd_start::text,'dnd_end',dnd_end::text,'dnd_days',dnd_days,'mail',mail_notifications,'calendar',calendar_reminders,'task',task_reminders,'policy',read_receipt_policy,'chat',chat_notifications,'updated_at',updated_at)::text FROM user_notification_prefs WHERE user_id={} ORDER BY device_fingerprint NULLS FIRST", account.user)).await?;
        notif.push(json!({"who":who,"rows":rows}));
        let rows = super::rows(owner, &format!("SELECT to_jsonb(sender_email)::text FROM vip_senders WHERE user_id={} ORDER BY created_at, sender_email", account.user)).await?;
        vip.push(json!({"who":who,"rows":rows}));
        let rows = super::rows(owner, &format!("SELECT jsonb_build_object('enabled',enabled,'subject',subject,'body_text',body_text,'body_html',body_html,'body_external',body_external,'body_external_html',body_external_html,'start_date',start_date,'end_date',end_date,'audience',external_audience,'only_contacts',only_contacts,'updated_at',updated_at)::text FROM vacation_settings WHERE mailbox_id={}", account.mailbox)).await?;
        vac.push(json!({"who":who,"rows":rows}));
        let rows = super::rows(owner, &format!("SELECT jsonb_build_object('delegate',CASE WHEN delegate_user_id={delegate} THEN '<delegate>' WHEN delegate_user_id={} THEN '<other>' ELSE delegate_user_id::text END,'starts_at',starts_at,'ends_at',ends_at,'created_at',created_at)::text FROM approval_delegations WHERE delegator_user_id={} ORDER BY id", b.user, account.user)).await?;
        del.push(json!({"who":who,"rows":rows}));
    }
    out.insert("notification_prefs".into(), json!(notif));
    out.insert("vip_senders".into(), json!(vip));
    out.insert("vacation".into(), json!(vac));
    out.insert("delegation".into(), json!(del));
    if seed.vars.contains_key("sync") {
        out.insert("devices".into(), json!(devices));
    }
    Ok(Value::Object(out))
}
