//! API-client commands from the second whole-CLI port slice.
use crate::{
    client::{Api, Failure},
    enabled, Options,
};
use serde_json::Value;

pub(super) fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}
pub(super) fn boolean(v: &Value, key: &str) -> bool {
    v[key].as_bool().unwrap_or(false)
}
pub(super) fn array(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

pub(super) fn feature(
    api: &Api,
    o: &Options,
    action: &str,
    args: &[String],
) -> Result<(), Failure> {
    if action == "set" {
        if args.len() < 2 {
            return Err("usage: mailctl feature set <key> <on|off>".into());
        }
        let (key, val) = (&args[0], &args[1]);
        if val != "on" && val != "off" {
            return Err(format!("value must be 'on' or 'off', got {val:?}").into());
        }
        let v = api.request("GET", "/admin/features", None, true)?;
        let t = array(&v)
            .iter()
            .find(|t| text(t, "key") == key)
            .ok_or_else(|| format!("no feature toggle found with key {key:?}"))?;
        if boolean(t, "confirmationRequired") {
            o.confirm(&format!("Set security feature {key} to {val}"))?;
        }
        api.request(
            "PUT",
            &format!("/admin/features/{key}"),
            Some(serde_json::json!({"enabled":val=="on"})),
            false,
        )?;
        println!("Feature {key} set to {val}.");
        return Ok(());
    }
    if action == "get" {
        let key = args.first().ok_or("usage: mailctl feature get <key>")?;
        let v = api.request("GET", "/admin/features", None, true)?;
        let t = array(&v)
            .iter()
            .find(|t| text(t, "key") == key)
            .ok_or_else(|| format!("no feature toggle found with key {key:?}"))?;
        if o.json {
            o.typed(
                &serde_json::from_value::<crate::models::Feature>(t.clone())
                    .map_err(|e| e.to_string())?,
            );
        } else {
            print!("{}: {}", key, enabled(boolean(t, "enabled")));
            if !text(t, "description").is_empty() {
                print!(" — {}", text(t, "description"));
            }
            println!();
        }
        return Ok(());
    }
    if action == "list" {
        let v = api.request("GET", "/admin/features", None, true)?;
        if o.json {
            o.typed(
                &serde_json::from_value::<Option<Vec<crate::models::Feature>>>(v.clone())
                    .map_err(|e| e.to_string())?,
            );
        } else if array(&v).is_empty() {
            println!("No feature toggles defined.");
        } else {
            println!("{:<45} {:<7} Description", "Key", "Enabled");
            for t in array(&v) {
                println!(
                    "{:<45} {:<7} {}",
                    text(t, "key"),
                    enabled(boolean(t, "enabled")),
                    text(t, "description")
                );
            }
        }
        return Ok(());
    }
    Err(format!("unknown feature action: {action} (try: list, get, set)").into())
}

pub(super) fn execute(
    api: &Api,
    o: &Options,
    cmd: &str,
    action: &str,
    args: &[String],
) -> Result<(), Failure> {
    match cmd {
        "identity" => crate::identity::run(api, o, action, args).map_err(crate::identity::exit),
        "office" => office(api, o, action, args),
        "role" => role(api, o, action, args),
        "approval" => approval(api, o, action, args),
        "ca" => ca(api, o, action, args),
        "eap" => eap(api, o, action, args),
        "mailbox" => mailbox(api, o, action, args),
        "audit" => audit(api, o, action, args),
        "upgrade" => upgrade(api, o, action, args),
        "quarantine" => quarantine(api, o, action, args),
        "feature" => feature(api, o, action, args),
        "device" => device(api, o, action, args),
        "policy" => policy(api, o, action, args),
        _ => unreachable!(),
    }
}
pub(super) fn need<'a>(args: &'a [String], n: usize, usage: &str) -> Result<&'a [String], Failure> {
    if args.len() < n {
        Err(usage.into())
    } else {
        Ok(args)
    }
}
fn device(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "list" {
        let v = api.request("GET", "/admin/mam/devices", None, true)?;
        o.output(&v["devices"]);
        return Ok(());
    }
    if action == "show" {
        let id = &need(args, 1, "usage: mailctl device show <device_id>")?[0];
        let v = api.request("GET", &format!("/admin/mdm/devices/{id}"), None, true)?;
        o.output(&v);
        return Ok(());
    }
    if action == "events" {
        let id = &need(args, 1, "usage: mailctl device events <device_id>")?[0];
        let v = api.request(
            "GET",
            &format!("/admin/mam/devices/{id}/events"),
            None,
            true,
        )?;
        o.output(&v["events"]);
        return Ok(());
    }
    if action == "lock" {
        let id = &need(args, 1, "usage: mailctl device lock <device_id>")?[0];
        o.confirm(&format!("Lock device {id}"))?;
        api.request("POST", &format!("/admin/mam/devices/{id}/lock"), None, true)?;
        return Ok(());
    }
    if action == "unlock" {
        let id = &need(args, 1, "usage: mailctl device unlock <device_id>")?[0];
        api.request(
            "POST",
            &format!("/admin/mam/devices/{id}/unlock"),
            None,
            true,
        )?;
        return Ok(());
    }
    if action == "policy" {
        let a = need(
            args,
            2,
            "usage: mailctl device policy <set|unset> <device_id> [key] [value]",
        )?;
        let id = &a[1];
        match a[0].as_str() {
            "set" => {
                need(
                    a,
                    4,
                    "usage: mailctl device policy set <device_id> <key> <value>",
                )?;
                api.request(
                    "PUT",
                    &format!("/admin/mam/devices/{id}/policy"),
                    Some(serde_json::json!({"policies":{&a[2]:&a[3]}})),
                    true,
                )?;
            }
            "unset" => {
                need(a, 3, "usage: mailctl device policy unset <device_id> <key>")?;
                api.request(
                    "DELETE",
                    &format!("/admin/mam/devices/{id}/policy/{}", a[2]),
                    None,
                    true,
                )?;
            }
            // device policy unset
            _ => {
                return Err(
                    format!("unknown device policy action: {}. Try: set, unset", a[0]).into(),
                )
            }
        }
        return Ok(());
    }
    if action == "wipe" {
        let id = &need(
            args,
            1,
            "usage: mailctl device wipe <device_id> [--level account|device]",
        )?[0];
        let fs = crate::flags::parse("device wipe", &args[1..], &["level"], &[], false);
        let level = if fs.set("level") {
            fs.get("level")
        } else {
            "account"
        };
        if level != "account" && level != "device" {
            return Err("level must be 'account' or 'device'".into());
        }
        o.confirm(&format!("Wipe device {id} (level: {level})"))?;
        api.request(
            "POST",
            &format!("/admin/mdm/devices/{id}/wipe"),
            Some(serde_json::json!({"level":level})),
            true,
        )?;
        return Ok(());
    }
    // device actions
    Err(format!(
        "unknown device action: {action}. Try: list, show, events, policy, lock, unlock, wipe"
    )
    .into())
}
fn policy(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "list" {
        let v = api.request("GET", "/admin/mam/policies", None, true)?;
        if !o.quiet {
            println!("Global policies:");
        }
        o.output(&v["global"]);
        if !o.quiet {
            println!("\nGroup policies:");
        }
        o.output(&v["groups"]);
        return Ok(());
    }
    if action == "set" {
        let a = need(args, 2, "usage: mailctl policy set <key> <value>")?;
        api.request(
            "PUT",
            "/admin/mam/policies",
            Some(serde_json::json!({"policies":{&a[0]:&a[1]}})),
            true,
        )?;
        return Ok(());
    }
    if action == "group" {
        let a = need(
            args,
            1,
            "usage: mailctl policy group <list|set|unset> [args...]",
        )?;
        match a[0].as_str() {
            "list" => {
                let v = api.request("GET", "/admin/mam/policies", None, true)?;
                o.output(&v["groups"]);
            }
            "set" => {
                need(
                    a,
                    5,
                    "usage: mailctl policy group set <group_type> <group_id> <key> <value>",
                )?;
                api.request("PUT","/admin/mam/policies/group",Some(serde_json::json!({"group_type":a[1],"group_id":a[2].parse::<i64>().unwrap_or(0),"policies":{&a[3]:&a[4]}})),true)?;
            }
            "unset" => {
                need(
                    a,
                    4,
                    "usage: mailctl policy group unset <group_type> <group_id> <key>",
                )?;
                api.request(
                    "DELETE",
                    &format!("/admin/mam/policies/group/{}/{}/{}", a[1], a[2], a[3]),
                    None,
                    true,
                )?;
            }
            // policy group actions
            _ => {
                return Err(format!(
                    "unknown policy group action: {}. Try: list, set, unset",
                    a[0]
                )
                .into())
            }
        }
        return Ok(());
    }
    if action == "template" {
        return policy_template(api, o, args);
    }
    // policy actions
    Err(format!("unknown policy action: {action}. Try: list, set, group, template").into())
}

fn private_write(path: &std::path::Path, data: &[u8], mode: u32) -> Result<(), Failure> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| e.to_string())?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(path)
        .and_then(|mut f| f.write_all(data))
        .map_err(|e| e.to_string().into())
}
fn policy_template(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let a = need(
        args,
        1,
        "usage: mailctl policy template <save|load|list> [name]",
    )?;
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        });
    let dir = base.join("mailctl/templates");
    if a[0] == "save" {
        let name = &need(a, 2, "usage: mailctl policy template save <name>")?[1];
        let v = api
            .request("GET", "/admin/mam/policies", None, true)
            .map_err(|e| format!("failed to fetch policies: {e}"))?;
        let path = dir.join(format!("{name}.json"));
        private_write(&path, crate::client::go_json(&v, true).as_bytes(), 0o600)?;
        if !o.quiet {
            println!("Template saved: {}", path.display());
        }
        return Ok(());
    }
    if a[0] == "list" {
        let entries = match std::fs::read_dir(&dir) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("(no templates)");
                return Ok(());
            }
            Err(e) => return Err(e.to_string().into()),
        };
        let mut entries = entries
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        entries.sort_by_key(|e| e.file_name());
        if entries.is_empty() {
            println!("(no templates)");
        }
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            if !e.path().is_dir() && name.len() > 5 {
                if let Some(name) = name.strip_suffix(".json") {
                    println!("{name}");
                }
            }
        }
        return Ok(());
    }
    if a[0] == "load" {
        let name = &need(a, 2, "usage: mailctl policy template load <name>")?[1];
        let path = dir.join(format!("{name}.json"));
        let raw = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "read template {name}: open {}: {}",
                path.display(),
                crate::flags::go_io_error(&e)
            )
        })?;
        let v: Value = serde_json::from_str(&raw).map_err(|e| format!("parse template: {e}"))?;
        let mut policies = serde_json::Map::new();
        for p in array(&v["global"]) {
            if !text(p, "policy_key").is_empty() {
                policies.insert(text(p, "policy_key").into(), text(p, "policy_value").into());
            }
        }
        if !policies.is_empty() {
            api.request(
                "PUT",
                "/admin/mam/policies",
                Some(serde_json::json!({"policies":policies})),
                true,
            )
            .map_err(|e| format!("apply global policies: {e}"))?;
            if !o.quiet {
                println!(
                    "Applied {} global policies from template {name:?}",
                    policies.len()
                );
            }
        }
        for p in array(&v["groups"]) {
            if !text(p, "group_type").is_empty() && !text(p, "policy_key").is_empty() {
                let _=api.request("PUT","/admin/mam/policies/group",Some(serde_json::json!({"group_type":text(p,"group_type"),"group_id":crate::client::go_value(&p["group_id"]).parse::<i64>().unwrap_or(0),"policies":{text(p,"policy_key"):text(p,"policy_value")}})),true);
            }
        }
        if !o.quiet {
            println!("Template {name:?} loaded.");
        }
        return Ok(());
    }
    // template actions
    Err(format!("unknown template action: {}. Try: save, load, list", a[0]).into())
}

pub(super) fn escape(raw: &str) -> String {
    let mut s = String::new();
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                s.push(b as char)
            }
            b' ' => s.push('+'),
            _ => s.push_str(&format!("%{b:02X}")),
        }
    }
    s
}
pub(super) fn query(pairs: Vec<(&str, String)>) -> String {
    let mut pairs = pairs;
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", escape(k), escape(&v)))
        .collect::<Vec<_>>()
        .join("&")
}
pub(super) fn number(v: &Value, key: &str) -> i64 {
    v[key].as_i64().unwrap_or(0)
}
fn truncate(raw: &str, n: usize) -> String {
    if raw.len() > n {
        format!("{}...", String::from_utf8_lossy(&raw.as_bytes()[..n - 3]))
    } else {
        raw.into()
    }
}
fn quarantine(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "list" {
        let fs = crate::flags::parse(
            "quarantine list",
            args,
            &["status", "q", "limit", "offset"],
            &[],
            false,
        );
        let mut qs = Vec::new();
        for k in ["status", "q", "limit", "offset"] {
            if !fs.get(k).is_empty() && fs.get(k) != "0" {
                qs.push((k, fs.get(k).into()));
            }
        }
        let q = query(qs);
        let path = if q.is_empty() {
            "/admin/quarantine".into()
        } else {
            format!("/admin/quarantine?{q}")
        };
        let v = api.request("GET", &path, None, true)?;
        let items = &v["items"];
        if o.json {
            o.typed(
                &serde_json::from_value::<Option<Vec<crate::models::Quarantine>>>(items.clone())
                    .map_err(|e| e.to_string())?,
            );
        } else if array(items).is_empty() {
            println!("No quarantined messages.");
        } else {
            println!(
                "{:<6} {:<30} {:<30} {:<15} Quarantined",
                "ID", "Subject", "From", "Reason"
            );
            for t in array(items) {
                let state = if !t["releasedAt"].is_null() {
                    "released"
                } else if !t["rejectedAt"].is_null() {
                    "rejected"
                } else {
                    "active"
                };
                println!(
                    "{:<6} {:<30} {:<30} {:<15} {} ({state})",
                    number(t, "id"),
                    truncate(text(t, "subject"), 30),
                    truncate(text(t, "fromAddr"), 30),
                    text(t, "reasonType"),
                    text(t, "quarantinedAt")
                );
            }
        }
        return Ok(());
    }
    if action == "stats" {
        let v = api.request("GET", "/admin/quarantine/stats", None, true)?;
        if o.json {
            o.output(&v);
        } else {
            println!(
                "Active:   {}\nReleased: {}\nRejected: {}",
                number(&v, "active"),
                number(&v, "released"),
                number(&v, "rejected")
            );
        }
        return Ok(());
    }
    if action == "preview" {
        let id = &need(args, 1, "usage: mailctl quarantine preview <id>")?[0];
        let v = api.request(
            "GET",
            &format!("/admin/quarantine/{id}/preview"),
            None,
            true,
        )?;
        if o.json {
            o.typed(
                &serde_json::from_value::<crate::models::QuarantinePreview>(v.clone())
                    .map_err(|e| e.to_string())?,
            );
        } else {
            println!(
                "Subject:       {}\nFrom:          {}\nQuarantined:   {}\n---\n{}",
                text(&v, "subject"),
                text(&v, "fromAddr"),
                text(&v, "quarantinedAt"),
                text(&v, "html")
            );
        }
        return Ok(());
    }
    if action == "release" {
        let id = &need(args, 1, "usage: mailctl quarantine release <id>")?[0];
        o.confirm(&format!(
            "Release quarantined message {id} to the recipient's inbox"
        ))?;
        api.request(
            "POST",
            &format!("/admin/quarantine/{id}/release"),
            None,
            false,
        )?;
        println!("Quarantined message {id} released.");
        return Ok(());
    }
    if action == "reject" {
        let id = &need(args, 1, "usage: mailctl quarantine reject <id>")?[0];
        o.confirm(&format!(
            "Reject (permanently delete) quarantined message {id}"
        ))?;
        api.request(
            "POST",
            &format!("/admin/quarantine/{id}/reject"),
            None,
            false,
        )?;
        println!("Quarantined message {id} rejected.");
        return Ok(());
    }
    // quarantine actions
    Err(
        format!("unknown quarantine action: {action} (try: list, stats, preview, release, reject)")
            .into(),
    )
}

pub(super) fn owns(cmd: &str) -> bool {
    if cmd == "identity" {
        return true;
    }
    if cmd == "office" {
        return true;
    }
    if cmd == "role" {
        return true;
    }
    if cmd == "approval" {
        return true;
    }
    matches!(
        cmd,
        "feature"
            | "device"
            | "policy"
            | "quarantine"
            | "upgrade"
            | "audit"
            | "mailbox"
            | "eap"
            | "ca"
    )
}

fn upgrade(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "status" {
        let v = api.with_headers("GET", "/admin/system/upgrades", None, true, &[], 2 << 20)?;
        o.output(&v);
        return Ok(());
    }
    if action == "history" {
        let v = api.with_headers("GET", "/admin/system/upgrades", None, true, &[], 2 << 20)?;
        if o.json {
            o.output(&v["history"]);
        } else {
            for t in array(&v["history"]) {
                println!(
                    "{}  {}  {}  {}",
                    crate::client::go_value(&t["createdAt"]),
                    crate::client::go_value(&t["intentId"]),
                    crate::client::go_value(&t["releaseId"]),
                    crate::client::go_value(&t["state"])
                );
            }
        }
        return Ok(());
    }
    if action == "watch" {
        let id = canonical(
            &need(
                args,
                1,
                "usage: mailctl upgrade watch <intent-id> [--interval 2s] [--timeout 10m]",
            )?[0],
        )?;
        let fs = crate::flags::parse(
            "upgrade watch",
            &args[1..],
            &["interval", "timeout"],
            &[],
            false,
        );
        let interval = duration(if fs.set("interval") {
            fs.get("interval")
        } else {
            "2s"
        });
        let timeout = duration(if fs.set("timeout") {
            fs.get("timeout")
        } else {
            "10m"
        });
        if !fs.positional.is_empty()
            || interval.is_none_or(|d| d.as_secs_f64() < 0.25 || d.as_secs() > 60)
            || timeout.is_none_or(|d| d.is_zero() || d.as_secs() > 86400)
        {
            return Err("invalid watch interval or timeout".into());
        }
        let interval = interval.unwrap();
        let timeout = timeout.unwrap();
        let deadline = std::time::Instant::now() + timeout;
        let mut prior = String::new();
        loop {
            let v = api.with_headers(
                "GET",
                &format!("/admin/system/upgrades/intents/{id}"),
                None,
                true,
                &[],
                1 << 20,
            )?;
            let state = text(&v, "state");
            if state != prior {
                if o.json {
                    o.output(&v);
                } else {
                    println!("{}  {state}", crate::client::go_value(&v["updatedAt"]));
                }
                prior = state.into();
            }
            if [
                "verified",
                "rolled_back",
                "failed",
                "recovery_required",
                "cancelled",
                "expired",
            ]
            .contains(&state)
            {
                return if ["verified", "rolled_back", "cancelled"].contains(&state) {
                    Ok(())
                } else {
                    Err(format!("upgrade reached terminal state {state}").into())
                };
            }
            if std::time::Instant::now() + interval > deadline {
                return Err(
                    format!("upgrade watch timed out after {}", duration_text(timeout)).into(),
                );
            }
            std::thread::sleep(interval);
        }
    }
    if action == "cancel" {
        let id = canonical(
            &need(
                args,
                1,
                "usage: mailctl upgrade cancel <intent-id> --generation <n> --reason <text>",
            )?[0],
        )?;
        let fs = crate::flags::parse(
            "upgrade cancel",
            &args[1..],
            &["generation", "reason"],
            &[],
            false,
        );
        if !fs.positional.is_empty() {
            return Err("invalid cancel arguments".into());
        }
        canonical(fs.get("generation")).map_err(|_| "invalid --generation")?;
        let reason = fs.get("reason");
        if reason.len() < 8 || reason.len() > 1024 {
            return Err("--reason must contain 8-1024 characters".into());
        }
        let v = api.with_headers(
            "POST",
            &format!("/admin/system/upgrades/intents/{id}/cancel"),
            Some(serde_json::json!({"expectedGeneration":fs.get("generation"),"reason":reason})),
            true,
            &[("X-Audit-Reason", reason.into())],
            0,
        )?;
        o.output(&v);
        return Ok(());
    }
    if action == "diagnostics" {
        let id = canonical(
            &need(
                args,
                1,
                "usage: mailctl upgrade diagnostics <intent-id> --output <file>",
            )?[0],
        )?;
        let fs = crate::flags::parse("upgrade diagnostics", &args[1..], &["output"], &[], false);
        if !fs.positional.is_empty() || fs.get("output").is_empty() {
            return Err("--output is required".into());
        }
        let v = api.with_headers(
            "GET",
            &format!("/admin/system/upgrades/intents/{id}/diagnostics"),
            None,
            true,
            &[],
            1 << 20,
        )?;
        let data = format!("{}\n", crate::client::go_json(&v, true));
        publish_new(fs.get("output"), data.as_bytes())
            .map_err(|e| format!("write diagnostics output: {e}"))?;
        println!("Sanitized diagnostics written to {}", fs.get("output"));
        return Ok(());
    }
    // upgrade actions
    Err(format!(
        "unknown upgrade action: {action} (try: status, watch, cancel, history, diagnostics)"
    )
    .into())
}

fn audit(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "export" {
        let fs = crate::flags::parse("audit export", args, &["out"], &[], false);
        let mut resp = api.stream_get("/admin/audit/csv")?;
        if fs.get("out").is_empty() {
            std::io::copy(&mut resp, &mut std::io::stdout()).map_err(|e| format!("write: {e}"))?;
        } else {
            let path = fs.get("out");
            let mut file = std::fs::File::create(path).map_err(|e| {
                format!(
                    "create {path}: open {path}: {}",
                    crate::flags::go_io_error(&e)
                )
            })?;
            std::io::copy(&mut resp, &mut file).map_err(|e| format!("write: {e}"))?;
            println!("Audit log exported to {path}");
        }
        return Ok(());
    }
    if action == "verify-chain" {
        let fs = crate::flags::parse("audit verify-chain", args, &["from", "to"], &[], false);
        let mut qs = Vec::new();
        for (k, out) in [("from", "from_id"), ("to", "to_id")] {
            let n = fs.get(k).parse::<i64>().unwrap_or(0);
            if n != 0 {
                qs.push((out, n.to_string()));
            }
        }
        let q = query(qs);
        let path = if q.is_empty() {
            "/admin/audit/verify".into()
        } else {
            format!("/admin/audit/verify?{q}")
        };
        let v = api.request("GET", &path, None, true)?;
        let rows = array(&v["chain"]);
        let broken = rows
            .iter()
            .filter(|r| !boolean(r, "valid"))
            .map(|r| number(r, "id"))
            .collect::<Vec<_>>();
        if o.json {
            o.typed(
                &serde_json::from_value::<crate::models::AuditChain>(v.clone())
                    .map_err(|e| e.to_string())?,
            );
        } else if broken.is_empty() {
            println!("Audit chain OK: {} row(s) verified.", rows.len());
        } else {
            println!(
                "Audit chain BROKEN: {}/{} row(s) failed verification (ids: [{}])",
                broken.len(),
                rows.len(),
                broken
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        if !broken.is_empty() {
            return Err(format!(
                "audit chain integrity check failed: {} broken row(s)",
                broken.len()
            )
            .into());
        }
        return Ok(());
    }
    // audit actions
    Err(format!("unknown audit action: {action} (try: export, verify-chain)").into())
}

fn canonical(raw: &str) -> Result<String, Failure> {
    if raw
        .parse::<i64>()
        .is_ok_and(|n| n > 0 && n.to_string() == raw)
    {
        Ok(raw.into())
    } else {
        Err(format!("invalid decimal identifier {raw:?}").into())
    }
}
pub(super) fn duration(raw: &str) -> Option<std::time::Duration> {
    let mut s = raw;
    let mut total = 0.0;
    if raw == "0" {
        return Some(std::time::Duration::ZERO);
    }
    while !s.is_empty() {
        let n = s
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len());
        if n == 0 {
            return None;
        }
        let val = s[..n].parse::<f64>().ok()?;
        s = &s[n..];
        let (unit, factor) = [
            ("ns", 1e-9),
            ("us", 1e-6),
            ("µs", 1e-6),
            ("ms", 1e-3),
            ("s", 1.0),
            ("m", 60.0),
            ("h", 3600.0),
        ]
        .into_iter()
        .find(|(u, _)| s.starts_with(u))?;
        s = &s[unit.len()..];
        total += val * factor;
    }
    std::time::Duration::try_from_secs_f64(total).ok()
}
pub(super) fn duration_text(d: std::time::Duration) -> String {
    let s = d.as_secs_f64();
    if s < 1.0 {
        format!("{}ms", s * 1000.0)
    } else {
        let secs = d.as_secs() % 60;
        let mins = d.as_secs() / 60 % 60;
        let hours = d.as_secs() / 3600;
        if hours > 0 {
            format!("{hours}h{mins}m{secs}s")
        } else if mins > 0 {
            format!("{mins}m{secs}s")
        } else {
            format!("{s}s")
        }
    }
}

pub(super) fn publish_new(path: &str, data: &[u8]) -> Result<(), Failure> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dest = std::path::Path::new(path);
    let dir = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let temp = dir.join(format!(".mailctl-private-artifact-{}", new_uuid()?));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| {
            format!(
                "create temporary private artifact: open {}: {}",
                temp.display(),
                crate::flags::go_io_error(&e)
            )
        })?;
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(temp.clone());
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|e| format!("chmod temporary private artifact: {e}"))?;
    f.write_all(data).map_err(|e| {
        format!(
            "write temporary private artifact: write {}: {}",
            temp.display(),
            crate::flags::go_io_error(&e)
        )
    })?;
    f.sync_all().map_err(|e| {
        format!(
            "sync temporary private artifact: sync {}: {}",
            temp.display(),
            crate::flags::go_io_error(&e)
        )
    })?;
    drop(f);
    std::fs::hard_link(&temp, dest).map_err(|e| {
        format!(
            "publish new private artifact: link {} {path}: {}",
            temp.display(),
            crate::flags::go_io_error(&e)
        )
    })?;
    std::fs::remove_file(&temp).map_err(|e| format!("temporary artifact cleanup failed: {e}"))?;
    std::fs::File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("sync private artifact directory: {e}"))?;
    Ok(())
}

fn mailbox(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "retained" {
        if !args.is_empty() {
            return Err("usage: mailctl mailbox retained".into());
        }
        let v = api.with_headers("GET", "/admin/mailboxes/retained", None, true, &[], 1 << 20)?;
        if !v.is_array() && !v.is_null() {
            return Err(
                "json: cannot unmarshal object into Go value of type []map[string]interface {}"
                    .into(),
            );
        }
        o.output(&v);
        return Ok(());
    }
    if action == "parity" {
        if !args.is_empty() {
            return Err("usage: mailctl mailbox parity".into());
        }
        let v = api.with_headers(
            "GET",
            "/admin/mailboxes/lifecycle/parity",
            None,
            true,
            &[],
            1 << 20,
        )?;
        o.output(&v);
        return Ok(());
    }
    if action == "preview" {
        if args.len() != 1 {
            return Err("usage: mailctl mailbox preview <mailbox-id>".into());
        }
        let id = positive(&args[0], "mailbox-id")?;
        let v = api.with_headers(
            "GET",
            &format!("/admin/mailboxes/{id}/lifecycle/preview"),
            None,
            true,
            &[],
            1 << 20,
        )?;
        o.output(&v);
        return Ok(());
    }
    if action == "suspend" {
        return mailbox_transition(api, o, action, args);
    }
    if action == "resume" {
        return mailbox_transition(api, o, action, args);
    }
    if action == "detach-retain" {
        return mailbox_transition(api, o, action, args);
    }
    if action == "reconnect" {
        return mailbox_transition(api, o, action, args);
    }
    if action == "purge-schedule" {
        let id=positive(&need(args,1,"usage: mailctl mailbox purge-schedule <mailbox-id> --generation N --preview-digest HEX --approver-user ID --reason TEXT")?[0],"mailbox-id")?;
        let f = crate::flags::parse(
            "mailbox purge-schedule",
            &args[1..],
            &["generation", "reason", "preview-digest", "approver-user"],
            &[],
            false,
        );
        if !f.positional.is_empty() {
            return Err("invalid purge-schedule flags".into());
        }
        positive(f.get("generation"), "generation")?;
        positive(f.get("approver-user"), "approver-user")?;
        if f.get("preview-digest").len() != 64 {
            return Err("--preview-digest must be a 64-character SHA-256 digest".into());
        }
        safe_reason(f.get("reason"))?;
        o.confirm(&format!("schedule permanent purge for mailbox {id}"))?;
        let key = new_uuid()?;
        return mailbox_post(
            api,
            o,
            &format!("/admin/mailboxes/{id}/purge"),
            f.get("reason"),
            &key,
            serde_json::json!({"expectedGeneration":f.get("generation"),"previewDigest":f.get("preview-digest").to_lowercase(),"approverUserId":f.get("approver-user"),"reason":f.get("reason"),"idempotencyKey":key}),
        );
    }
    if action == "purge-approve" {
        let id = positive(
            &need(
                args,
                1,
                "usage: mailctl mailbox purge-approve <approval-id> [--comment TEXT]",
            )?[0],
            "approval-id",
        )?;
        let f = crate::flags::parse(
            "mailbox purge-approve",
            &args[1..],
            &["comment"],
            &[],
            false,
        );
        if !f.positional.is_empty() || f.get("comment").len() > 1024 {
            return Err("invalid purge approval flags".into());
        }
        o.confirm(&format!("approve permanent mailbox purge request {id}"))?;
        return mailbox_post(
            api,
            o,
            &format!("/admin/mailbox-purge-approvals/{id}"),
            "",
            "",
            serde_json::json!({"decision":"approve","comment":f.get("comment")}),
        );
    }
    if action == "purge-deny" {
        let id = positive(
            &need(
                args,
                1,
                "usage: mailctl mailbox purge-deny <approval-id> [--comment TEXT]",
            )?[0],
            "approval-id",
        )?;
        let f = crate::flags::parse("mailbox purge-deny", &args[1..], &["comment"], &[], false);
        if !f.positional.is_empty() || f.get("comment").len() > 1024 {
            return Err("invalid purge approval flags".into());
        }
        return mailbox_post(
            api,
            o,
            &format!("/admin/mailbox-purge-approvals/{id}"),
            "",
            "",
            serde_json::json!({"decision":"deny","comment":f.get("comment")}),
        );
    }
    if action == "purge-cancel" {
        let raw = &need(
            args,
            1,
            "usage: mailctl mailbox purge-cancel <purge-id> --reason TEXT",
        )?[0];
        let id = uuid(raw)
            .filter(|s| s != "00000000-0000-0000-0000-000000000000")
            .ok_or("purge-id must be a UUID")?;
        let f = crate::flags::parse("mailbox purge-cancel", &args[1..], &["reason"], &[], false);
        if !f.positional.is_empty() {
            return Err("invalid purge-cancel flags".into());
        }
        safe_reason(f.get("reason"))?;
        let key = new_uuid()?;
        return mailbox_post(
            api,
            o,
            &format!("/admin/mailbox-purges/{id}/cancel"),
            f.get("reason"),
            &key,
            serde_json::json!({"reason":f.get("reason"),"idempotencyKey":key}),
        );
    }
    if action == "purge-execute" {
        let raw = &need(
            args,
            1,
            "usage: mailctl mailbox purge-execute <purge-id> --reason TEXT",
        )?[0];
        let id = uuid(raw)
            .filter(|s| s != "00000000-0000-0000-0000-000000000000")
            .ok_or("purge-id must be a UUID")?;
        let f = crate::flags::parse("mailbox purge-execute", &args[1..], &["reason"], &[], false);
        if !f.positional.is_empty() {
            return Err("invalid purge-execute flags".into());
        }
        safe_reason(f.get("reason"))?;
        o.confirm(&format!("permanently purge mailbox request {id}"))?;
        let key = new_uuid()?;
        return mailbox_post(
            api,
            o,
            &format!("/admin/mailbox-purges/{id}/execute"),
            f.get("reason"),
            &key,
            serde_json::json!({"reason":f.get("reason"),"idempotencyKey":key}),
        );
    }
    // mailbox actions
    Err(format!("unknown mailbox action: {action}").into())
}

fn positive(raw: &str, name: &str) -> Result<String, Failure> {
    let id = raw
        .parse::<i64>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| format!("{name} must be a positive decimal identifier"))?;
    Ok(id.to_string())
}

fn safe_reason(reason: &str) -> Result<(), Failure> {
    if reason.len() < 8
        || reason.len() > 1024
        || reason.trim() != reason
        || reason.contains(['\r', '\n', '\0'])
    {
        Err(
            "--reason must contain 8-1024 safe characters without leading/trailing whitespace"
                .into(),
        )
    } else {
        Ok(())
    }
}
pub(super) fn new_uuid() -> Result<String, Failure> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("generate idempotency key: {e}"))?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let h = b.iter().map(|n| format!("{n:02x}")).collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn mailbox_post(
    api: &Api,
    o: &Options,
    path: &str,
    reason: &str,
    key: &str,
    body: Value,
) -> Result<(), Failure> {
    let mut headers = Vec::new();
    if !reason.is_empty() {
        headers.push(("X-Audit-Reason", reason.into()));
    }
    if !key.is_empty() {
        headers.push(("Idempotency-Key", key.into()));
    }
    let v = api.with_headers("POST", path, Some(body), true, &headers, 1 << 20)?;
    o.output(&v);
    Ok(())
}
fn mailbox_transition(
    api: &Api,
    o: &Options,
    action: &str,
    args: &[String],
) -> Result<(), Failure> {
    let id = positive(
        &need(
            args,
            1,
            &format!("usage: mailctl mailbox {action} <mailbox-id> --generation N --reason TEXT"),
        )?[0],
        "mailbox-id",
    )?;
    let f = crate::flags::parse(
        &format!("mailbox {action}"),
        &args[1..],
        &[
            "generation",
            "reason",
            "target-user",
            "evidence-kind",
            "identity-link",
            "link-generation",
            "source-key-digest",
            "delivery",
        ],
        &[],
        false,
    );
    if !f.positional.is_empty() {
        return Err(format!("invalid mailbox {action} flags").into());
    }
    positive(f.get("generation"), "generation")?;
    safe_reason(f.get("reason"))?;
    let key = new_uuid()?;
    let mut body = serde_json::json!({"action":action.replace('-',"_"),"expectedGeneration":f.get("generation"),"reason":f.get("reason"),"idempotencyKey":key});
    if !f.get("delivery").is_empty() {
        if !["accepting", "rejecting"].contains(&f.get("delivery")) {
            return Err("--delivery must be accepting or rejecting".into());
        }
        body["delivery"] = f.get("delivery").into();
    }
    if action == "reconnect" {
        positive(f.get("target-user"), "target-user")?;
        let kind = f.get("evidence-kind");
        if !["local_user", "identity_link"].contains(&kind) {
            return Err("--evidence-kind must be local_user or identity_link".into());
        }
        body["targetUserId"] = f.get("target-user").into();
        body["evidenceKind"] = kind.into();
        if kind == "identity_link" {
            positive(f.get("identity-link"), "identity-link")?;
            positive(f.get("link-generation"), "link-generation")?;
            if f.get("source-key-digest").len() != 64 {
                return Err("--source-key-digest must be a 64-character SHA-256 digest".into());
            }
            body["identityLinkId"] = f.get("identity-link").into();
            body["linkGeneration"] = f.get("link-generation").into();
            body["sourceKeyDigest"] = f.get("source-key-digest").to_lowercase().into();
        }
    }
    if ["suspend", "detach-retain"].contains(&action) {
        o.confirm(&format!("{action} mailbox {id}"))?;
    }
    mailbox_post(
        api,
        o,
        &format!("/admin/mailboxes/{id}/lifecycle"),
        f.get("reason"),
        &key,
        body,
    )
}

pub(super) fn uuid(raw: &str) -> Option<String> {
    let s = raw.strip_prefix("urn:uuid:").unwrap_or(raw);
    let s = s
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(s);
    let h = s.replace('-', "");
    if h.len() != 32 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if s.len() != 32
        && (s.len() != 36
            || !s.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            }))
    {
        return None;
    }
    let h = h.to_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

fn eap(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    let path = "/admin/email-address-policies";
    if action == "list" {
        let v = api.request("GET", path, None, true)?;
        let rows: Option<Vec<crate::models::Eap>> =
            serde_json::from_value(v).map_err(|e| e.to_string())?;
        if o.json {
            o.typed(&rows);
        } else if rows.as_ref().is_none_or(Vec::is_empty) {
            println!("No email address policies defined.");
        } else {
            println!(
                "{:<4} {:<25} {:<7} {:<8} {:<40} Updated",
                "#", "Name", "Enabled", "Overwrite", "PrimaryTemplate"
            );
            for p in rows.unwrap() {
                println!(
                    "{:<4} {:<25} {:<7} {:<8} {:<40} {}",
                    p.priority,
                    p.name,
                    enabled(p.enabled),
                    if p.overwrite_directory_address {
                        "yes"
                    } else {
                        "no"
                    },
                    p.primary_template,
                    p.updated_at
                );
            }
        }
        return Ok(());
    }
    if action == "create" {
        let f = crate::flags::parse(
            "eap create",
            args,
            &[
                "name",
                "primary",
                "additional",
                "cond-department",
                "cond-domain-ids",
                "cond-mailbox-type",
                "cond-ad-ou",
                "duplicate-resolution",
            ],
            &["enabled", "overwrite"],
            false,
        );
        if f.get("name").is_empty() {
            return Err("--name is required".into());
        }
        if f.get("primary").is_empty() {
            return Err("--primary is required".into());
        }
        let mut body = serde_json::json!({"name":f.get("name"),"primaryTemplate":f.get("primary"),"enabled":!f.set("enabled")||f.boolean("enabled"),"overwriteDirectoryAddress":f.boolean("overwrite")});
        eap_fields(&f, &mut body)?;
        api.raw_json(
            "POST",
            path,
            raw_map(
                &body,
                &[
                    ("additionalTemplates", f.get("additional")),
                    ("condDepartment", f.get("cond-department")),
                    ("condDomainIds", f.get("cond-domain-ids")),
                    ("condMailboxType", f.get("cond-mailbox-type")),
                    ("condAdOu", f.get("cond-ad-ou")),
                ],
            )?
            .into_bytes(),
            false,
        )?;
        println!("Email address policy created.");
        return Ok(());
    }
    if action == "update" {
        let f = crate::flags::parse(
            "eap update",
            args,
            &[
                "id",
                "name",
                "primary",
                "additional",
                "overwrite",
                "cond-department",
                "cond-domain-ids",
                "cond-mailbox-type",
                "cond-ad-ou",
                "duplicate-resolution",
            ],
            &["enabled"],
            false,
        );
        let id = f.get("id").parse::<i64>().unwrap_or(0);
        if id == 0 {
            return Err("--id is required".into());
        }
        let mut body = serde_json::json!({});
        for (k, out) in [("name", "name"), ("primary", "primaryTemplate")] {
            if !f.get(k).is_empty() {
                body[out] = f.get(k).into();
            }
        }
        if f.set("enabled") {
            body["enabled"] = f.boolean("enabled").into();
        }
        if !f.get("overwrite").is_empty() {
            body["overwriteDirectoryAddress"] = (f.get("overwrite") == "true").into();
        }
        eap_fields(&f, &mut body)?;
        api.raw_json(
            "PUT",
            &format!("{path}/{id}"),
            raw_map(
                &body,
                &[
                    ("additionalTemplates", f.get("additional")),
                    ("condDepartment", f.get("cond-department")),
                    ("condDomainIds", f.get("cond-domain-ids")),
                    ("condMailboxType", f.get("cond-mailbox-type")),
                    ("condAdOu", f.get("cond-ad-ou")),
                ],
            )?
            .into_bytes(),
            false,
        )?;
        println!("Email address policy {id} updated.");
        return Ok(());
    }
    if action == "delete" {
        let id = &need(args, 1, "usage: mailctl eap delete <id>")?[0];
        o.confirm(&format!("Delete email address policy {id}"))?;
        api.request("DELETE", &format!("{path}/{id}"), None, false)?;
        println!("Email address policy {id} deleted.");
        return Ok(());
    }
    if action == "apply" {
        let f = crate::flags::parse("eap apply", args, &["id"], &[], false);
        let id = f.get("id").parse::<i64>().unwrap_or(0);
        let v = api.request(
            "POST",
            &format!("{path}/apply"),
            Some(serde_json::json!({"policyId":if id==0{None}else{Some(id)}})),
            true,
        )?;
        println!("Apply job enqueued: jobId={}", number(&v, "jobId"));
        return Ok(());
    }
    if action == "reorder" {
        need(args, 1, "usage: mailctl eap reorder <id1> <id2> ...")?;
        let ids = args
            .iter()
            .map(|s| decimal(s, "ID"))
            .collect::<Result<Vec<_>, _>>()?;
        api.request(
            "POST",
            &format!("{path}/reorder"),
            Some(serde_json::json!({"order":ids})),
            false,
        )?;
        println!("Email address policy order updated.");
        return Ok(());
    }
    // eap actions
    Err(
        format!("unknown eap action: {action} (try: list, create, update, delete, apply, reorder)")
            .into(),
    )
}

fn eap_fields(f: &crate::flags::Flags, body: &mut Value) -> Result<(), Failure> {
    for (k, out) in [
        ("additional", "additionalTemplates"),
        ("cond-department", "condDepartment"),
        ("cond-domain-ids", "condDomainIds"),
        ("cond-mailbox-type", "condMailboxType"),
        ("cond-ad-ou", "condAdOu"),
    ] {
        if !f.get(k).is_empty() {
            body[out] = serde_json::from_str(f.get(k)).map_err(|e| format!("marshal: {e}"))?;
        }
    }
    if !f.get("duplicate-resolution").is_empty() {
        body["duplicateResolution"] = f.get("duplicate-resolution").into();
    }
    Ok(())
}

fn decimal(raw: &str, label: &str) -> Result<i64, Failure> {
    raw.parse::<i64>().map_err(|e| {
        format!(
            "invalid {label} {raw:?}: strconv.ParseInt: parsing {raw:?}: {}",
            if matches!(
                e.kind(),
                std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow
            ) {
                "value out of range"
            } else {
                "invalid syntax"
            }
        )
        .into()
    })
}

fn ca(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    let path = "/admin/conditional-access/policies";
    if action == "list" {
        let v = api.request("GET", path, None, true)?;
        let rows: Option<Vec<crate::models::Ca>> =
            serde_json::from_value(v).map_err(|e| e.to_string())?;
        if o.json {
            o.typed(&rows);
        } else if rows.as_ref().is_none_or(Vec::is_empty) {
            println!("No conditional access policies defined.");
        } else {
            println!(
                "{:<4} {:<25} {:<15} {:<7} Updated",
                "#", "Name", "Scope", "Enabled"
            );
            for p in rows.unwrap() {
                let scope = if p.scope_target.is_empty() {
                    p.scope_type
                } else {
                    format!("{}:{}", p.scope_type, p.scope_target)
                };
                println!(
                    "{:<4} {:<25} {:<15} {:<7} {}",
                    p.priority,
                    p.name,
                    scope,
                    enabled(p.enabled),
                    p.updated_at
                );
            }
        }
        return Ok(());
    }
    if action == "create" {
        let f = crate::flags::parse(
            "ca create",
            args,
            &[
                "name",
                "desc",
                "state",
                "enabled",
                "scope",
                "target",
                "conditions",
                "actions",
            ],
            &[],
            false,
        );
        if f.get("name").is_empty() {
            return Err("--name is required".into());
        }
        let state = ca_state(
            if f.set("state") {
                f.get("state")
            } else {
                "report_only"
            },
            f.get("enabled"),
        );
        let body = serde_json::json!({"name":f.get("name"),"description":f.get("desc"),"state":state,"scope_type":if f.set("scope"){f.get("scope")}else{"user"},"scope_target":f.get("target"),"conditions":json_arg(if f.set("conditions"){f.get("conditions")}else{"{}"},"marshal: error calling MarshalJSON for type json.RawMessage: ")?,"actions":json_arg(if f.set("actions"){f.get("actions")}else{"{}"},"marshal: error calling MarshalJSON for type json.RawMessage: ")?});
        api.raw_json(
            "POST",
            path,
            raw_map(
                &body,
                &[
                    ("conditions", f.get("conditions")),
                    ("actions", f.get("actions")),
                ],
            )?
            .into_bytes(),
            false,
        )?;
        println!("Policy created.");
        return Ok(());
    }
    if action == "update" {
        let f = crate::flags::parse(
            "ca update",
            args,
            &[
                "id",
                "name",
                "desc",
                "state",
                "enabled",
                "scope",
                "target",
                "conditions",
                "actions",
            ],
            &[],
            false,
        );
        let id = f.get("id").parse::<i64>().unwrap_or(0);
        if id == 0 {
            return Err("--id is required".into());
        }
        let mut body = serde_json::json!({});
        for (k, out) in [
            ("name", "name"),
            ("desc", "description"),
            ("scope", "scope_type"),
            ("target", "scope_target"),
        ] {
            if !f.get(k).is_empty() {
                body[out] = f.get(k).into();
            }
        }
        let state = ca_state(f.get("state"), f.get("enabled"));
        if !state.is_empty() {
            body["state"] = state.into();
        }
        for k in ["conditions", "actions"] {
            if !f.get(k).is_empty() {
                body[k] = json_arg(
                    f.get(k),
                    "marshal: error calling MarshalJSON for type json.RawMessage: ",
                )?;
            }
        }
        api.raw_json(
            "PUT",
            &format!("{path}/{id}"),
            raw_map(
                &body,
                &[
                    ("conditions", f.get("conditions")),
                    ("actions", f.get("actions")),
                ],
            )?
            .into_bytes(),
            false,
        )?;
        println!("Policy {id} updated.");
        return Ok(());
    }
    if action == "delete" {
        let id = &need(args, 1, "usage: mailctl ca delete <id>")?[0];
        o.confirm(&format!("Delete conditional-access policy {id}"))?;
        api.request("DELETE", &format!("{path}/{id}"), None, false)?;
        println!("Policy {id} deleted.");
        return Ok(());
    }
    if action == "reorder" {
        need(args, 1, "usage: mailctl ca reorder <id1> <id2> ...")?;
        api.request(
            "POST",
            &format!("{path}/reorder"),
            Some(serde_json::json!({"order":args})),
            false,
        )?;
        println!("Policy order updated.");
        return Ok(());
    }
    if action == "export" {
        let mut resp = api
            .stream_get("/admin/conditional-access/export")
            .map_err(ca_exit)?;
        std::io::copy(&mut resp, &mut std::io::stdout()).map_err(|e| e.to_string())?;
        return Ok(());
    }
    if action == "import" {
        let f = crate::flags::parse("ca import", args, &["f", "mode"], &[], false);
        let raw = read_document(&f, false)?;
        let doc = json_arg(&raw, "invalid JSON: ")?;
        let mode = if f.set("mode") {
            f.get("mode")
        } else {
            "merge"
        };
        api.request(
            "POST",
            &format!("/admin/conditional-access/import?mode={mode}"),
            Some(doc),
            false,
        )
        .map_err(ca_exit)?;
        println!("Import complete.");
        return Ok(());
    }
    if action == "apply" {
        let f = crate::flags::parse("ca apply", args, &["f"], &["prune"], false);
        let raw = read_document(&f, false)?;
        let doc = json_arg(&raw, "invalid JSON: ")?;
        let mode = if f.boolean("prune") {
            "prune"
        } else {
            "replace"
        };
        api.request(
            "POST",
            &format!("/admin/conditional-access/import?mode={mode}"),
            Some(doc),
            false,
        )
        .map_err(ca_exit)?;
        println!("Apply complete.");
        return Ok(());
    }
    if action == "diff" {
        return ca_diff(api, args);
    }
    if action == "plan" {
        return ca_diff(api, args);
    }
    if action == "migrate" {
        let v = api
            .request("POST", "/admin/conditional-access/migrate", None, true)
            .map_err(ca_exit)?;
        json_always(&v);
        return Ok(());
    }
    if action == "promote" {
        let f = crate::flags::parse("ca promote", args, &["id"], &["yes"], false);
        let id = f.get("id").parse::<i64>().unwrap_or(0);
        if id == 0 {
            return Err("--id is required".into());
        }
        let impact = api
            .request("GET", &format!("{path}/{id}/impact"), None, true)
            .map_err(ca_exit)?;
        if number(&impact, "would_block") > 0 && !f.boolean("yes") {
            return Err(format!(
                "promote would block {} user(s) — add --yes to confirm",
                number(&impact, "would_block")
            )
            .into());
        }
        let v = api
            .request(
                "POST",
                &format!("{path}/{id}/promote"),
                Some(serde_json::json!({"confirm":true})),
                true,
            )
            .map_err(ca_exit)?;
        json_always(&v);
        println!("Policy {id} promoted to enforced.");
        return Ok(());
    }
    if action == "init" {
        let slug = &need(args, 1, "usage: mailctl ca init <template-slug>")?[0];
        let v = api
            .request(
                "POST",
                &format!("/admin/conditional-access/templates/{slug}/instantiate"),
                None,
                true,
            )
            .map_err(ca_exit)?;
        json_always(&v);
        println!("Policy instantiated from template {slug:?}.");
        return Ok(());
    }
    if action == "why" {
        let f = crate::flags::parse("ca why", args, &["correlation"], &[], false);
        let user = f
            .positional
            .first()
            .filter(|s| !s.is_empty())
            .ok_or("usage: mailctl ca why <email-or-user-id>")?;
        let mut path = format!("/admin/conditional-access/why-lookup?user={}", escape(user));
        if !f.get("correlation").is_empty() {
            path.push_str(&format!("&correlation={}", escape(f.get("correlation"))));
        }
        let v = api.request("GET", &path, None, true).map_err(ca_exit)?;
        json_always(&v);
        return Ok(());
    }
    if action == "simulate" {
        let f = crate::flags::parse(
            "ca simulate",
            args,
            &["user", "ip", "device-trust", "expect"],
            &[],
            false,
        );
        if f.get("user").is_empty() {
            return Err("--user is required".into());
        }
        let mut body = serde_json::json!({"user":f.get("user")});
        for (k, out) in [("ip", "ip"), ("device-trust", "device_trust")] {
            if !f.get(k).is_empty() {
                body[out] = f.get(k).into();
            }
        }
        let v = api
            .request(
                "POST",
                "/admin/conditional-access/simulate",
                Some(body),
                true,
            )
            .map_err(ca_exit)?;
        #[derive(serde::Serialize)]
        struct Simulation {
            decision: String,
            matched_by: Value,
        }
        Options {
            json: true,
            ..Options::default()
        }
        .typed(&Simulation {
            decision: text(&v, "decision").into(),
            matched_by: v["matched_by"].clone(),
        });
        if !f.get("expect").is_empty() && f.get("expect") != text(&v, "decision") {
            return Err(format!(
                "simulate: expected {:?}, got {:?}",
                f.get("expect"),
                text(&v, "decision")
            )
            .into());
        }
        return Ok(());
    }
    if action == "coverage" {
        let f = crate::flags::parse("ca coverage", args, &[], &["fail-on-gap"], false);
        let v = api
            .request("GET", "/admin/conditional-access/coverage", None, true)
            .map_err(ca_exit)?;
        #[derive(serde::Serialize)]
        struct Coverage {
            gaps: i64,
            shadowed: i64,
        }
        Options {
            json: true,
            ..Options::default()
        }
        .typed(&Coverage {
            gaps: number(&v, "gaps"),
            shadowed: number(&v, "shadowed"),
        });
        if f.boolean("fail-on-gap") && number(&v, "gaps") > 0 {
            return Err(format!("coverage: {} gap(s) found", number(&v, "gaps")).into());
        }
        return Ok(());
    }
    if action == "signin-log" {
        let f = crate::flags::parse(
            "ca signin-log",
            args,
            &["limit", "user", "correlation"],
            &[],
            false,
        );
        let limit = if f.set("limit") {
            f.get("limit").parse::<i64>().unwrap_or(0)
        } else {
            50
        };
        let mut path = format!("/admin/conditional-access/signin-log?limit={limit}");
        if !f.get("user").is_empty() {
            path.push_str(&format!("&user_id={}", escape(f.get("user"))));
        }
        if !f.get("correlation").is_empty() {
            path.push_str(&format!("&correlation_id={}", escape(f.get("correlation"))));
        }
        let v = api.request("GET", &path, None, true).map_err(ca_exit)?;
        json_always(&Value::Array(array(&v["rows"]).to_vec()));
        return Ok(());
    }
    if action == "install-pack" {
        let path = &need(args, 1, "usage: mailctl ca install-pack <pack-file.json>")?[0];
        let v = json_arg(&read_path(path)?, "invalid JSON: ")?;
        api.request(
            "POST",
            "/admin/conditional-access/import?mode=merge",
            Some(v),
            false,
        )
        .map_err(ca_exit)?;
        println!("Pack installed from {path}.");
        return Ok(());
    }
    if action == "pack" {
        let a = need(args, 1, "usage: mailctl ca pack diff <pack-file.json>")?;
        if a[0] != "diff" {
            return Err(format!("ca pack: unknown sub-command {:?} (use: diff)", a[0]).into());
        }
        need(a, 2, "usage: mailctl ca pack diff <pack-file.json>")?;
        return ca_diff(api, &["-f".into(), a[1].clone()]);
    }
    if action == "doctor" {
        let f = crate::flags::parse("ca doctor", args, &[], &["json"], false);
        let v = api
            .request("GET", "/admin/conditional-access/doctor", None, true)
            .map_err(ca_exit)?;
        let report: crate::models::CaDoctor =
            serde_json::from_value(v).map_err(|e| e.to_string())?;
        if f.boolean("json") {
            Options {
                json: true,
                ..Options::default()
            }
            .typed(&report);
            return Ok(());
        }
        println!(
            "CA health: {}/{} checks passed\n",
            report.score, report.total
        );
        for c in report.checks.unwrap_or_default() {
            println!(
                "  {} {}",
                if c.passed { "[PASS]" } else { "[FAIL]" },
                c.name
            );
            if !c.next_action.is_empty() {
                println!("       → {}", c.next_action);
            }
        }
        let stale = report.hygiene.stale_report_only.unwrap_or_default();
        if !stale.is_empty() {
            println!(
                "\nHygiene: {} stale report_only policy/policies (>30d):",
                stale.len()
            );
            for p in stale {
                println!(
                    "  [id={}] {} — {}d in report_only",
                    p.id, p.name, p.days_since_created
                );
            }
            println!("  → Promote or disable to keep policies actionable.");
        }
        if let Some(t) = report.time_to_first_policy_sec {
            println!("\nTime to first enforcing policy: {t}s");
        }
        if report.score < report.total {
            return Err("ca doctor: not all checks passed".into());
        }
        return Ok(());
    }
    if action == "fmt" {
        let path = &need(args, 1, "usage: mailctl ca fmt <file.json>")?[0];
        let doc = json_arg(&read_path(path)?, "invalid JSON: ")?;
        json_always(&doc);
        return Ok(());
    }
    if action == "explain" {
        let code = &need(args, 1, "usage: mailctl ca explain <BZnnn>")?[0];
        let dictionary: Value = serde_json::from_str(include_str!("ca_errors.json")).unwrap();
        if let Some(s) = dictionary[code].as_str() {
            println!("{s}");
        } else {
            println!("{code}: unrecognised error code — check the CA error reference at docs/design/security/ca-errors.md #{code}");
        }
        return Ok(());
    }
    if action == "validate" {
        let f = crate::flags::parse("ca validate", args, &[], &["strict"], false);
        let path = f
            .positional
            .first()
            .ok_or("usage: mailctl ca validate [--strict] <file.json>")?;
        let doc = json_arg(&read_path(path)?, "BZ085: invalid JSON: ").map_err(|e| e.exit(2))?;
        let warnings = crate::ca_schema::validate(&doc).map_err(|e| e.exit(2))?;
        for w in &warnings {
            eprintln!("warning: {w}");
        }
        if f.boolean("strict") && !warnings.is_empty() {
            return Err(format!(
                "validation failed: {} warning(s) (--strict)",
                warnings.len()
            )
            .into());
        }
        println!("{path}: OK (schemaVersion 1)");
        return Ok(());
    }
    // ca actions
    Err(format!("unknown ca action: {action} (try: list, create, update, delete, reorder, export, import, validate, apply, diff, plan, fmt, migrate, promote, init, why, simulate, coverage, doctor, explain, install-pack, pack, signin-log)").into())
}

fn ca_state(state: &str, alias: &str) -> String {
    if alias.is_empty() {
        state.into()
    } else {
        eprintln!("warning: --enabled is deprecated; use --state (report_only|on|off)");
        if alias == "true" {
            "on".into()
        } else {
            "off".into()
        }
    }
}
pub(super) fn json_arg(raw: &str, prefix: &str) -> Result<Value, Failure> {
    serde_json::from_str(raw)
        .map_err(|e| format!("{prefix}{}", crate::client::json_error(raw, &e, false)).into())
}

fn ca_exit(e: Failure) -> Failure {
    let s = &e.message;
    let code = if s.contains("HTTP 403") || s.contains("HTTP 401") {
        3
    } else if s.contains("HTTP 409") || s.contains("BZ087") {
        4
    } else {
        e.code
    };
    e.exit(code)
}

pub(super) fn read_path(path: &str) -> Result<String, Failure> {
    if path.is_empty() {
        return Err("usage: -f <file.json> (or pass file as first positional arg)".into());
    }
    if path == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).map_err(|e| {
            format!(
                "read {path}: open {path}: {}",
                crate::flags::go_io_error(&e)
            )
            .into()
        })
    }
}
fn read_document(f: &crate::flags::Flags, read_doc: bool) -> Result<String, Failure> {
    let path = if !f.get("f").is_empty() {
        f.get("f")
    } else {
        f.positional.first().map(String::as_str).unwrap_or("")
    };
    if path.is_empty() && read_doc {
        return Err("usage: -f <file.json> (or pass file as positional arg)".into());
    }
    read_path(path)
}

fn ca_diff(api: &Api, args: &[String]) -> Result<(), Failure> {
    let f = crate::flags::parse("", args, &["f"], &[], false);
    let doc = json_arg(&read_document(&f, true)?, "invalid JSON: ")?;
    let v = api
        .request("POST", "/admin/conditional-access/diff", Some(doc), true)
        .map_err(ca_exit)?;
    #[derive(serde::Serialize)]
    struct Diff {
        drift: bool,
        changes: Value,
    }
    let result = Diff {
        drift: boolean(&v, "drift"),
        changes: v["changes"].clone(),
    };
    Options {
        json: true,
        ..Options::default()
    }
    .typed(&result);
    if result.drift {
        Err(Failure::from("changes present").exit(2))
    } else {
        Ok(())
    }
}

fn json_always(v: &Value) {
    println!("{}", crate::client::go_json_generic(v, true));
}

pub(super) fn compact_json(raw: &str) -> Result<String, Failure> {
    json_arg(
        raw,
        "marshal: error calling MarshalJSON for type json.RawMessage: ",
    )?;
    let mut out = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in raw.chars() {
        if quoted {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
            out.push(c);
        } else if !c.is_ascii_whitespace() {
            out.push(c);
        }
    }
    Ok(out
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}
pub(super) fn raw_map(body: &Value, fields: &[(&str, &str)]) -> Result<String, Failure> {
    let mut entries = Vec::new();
    for (k, v) in body.as_object().unwrap() {
        let raw = fields
            .iter()
            .find(|(name, raw)| *name == k && !raw.is_empty())
            .map(|(_, raw)| *raw);
        let value = match raw {
            Some(s) => compact_json(s)?,
            None => crate::client::go_json(v, false),
        };
        entries.push(format!(
            "{}:{value}",
            crate::client::go_json(&k.clone().into(), false)
        ));
    }
    Ok(format!("{{{}}}", entries.join(",")))
}

fn approval_path(consumer: &str) -> String {
    let p = "/admin/approval-policies";
    if consumer.is_empty() {
        p.into()
    } else {
        format!("{p}?consumer_type={}", escape(consumer))
    }
}
fn approval(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    let path = "/admin/approval-policies";
    if action == "list" {
        let f = crate::flags::parse("approval list", args, &["consumer-type"], &[], false);
        let (v, ordered) = wire_request(
            api,
            "[]approvalPolicy",
            "GET",
            &approval_path(f.get("consumer-type")),
            None,
            &[],
            0,
        )?;
        if o.json {
            wire_output(o, &ordered);
        } else if array(&v).is_empty() {
            println!("No approval policies defined.");
        } else {
            println!(
                "{:<4} {:<24} {:<28} {:<8} {:<8} {:<3} Updated",
                "ID", "ConsumerType", "Name", "Enabled", "Requires", "Pri"
            );
            for p in array(&v) {
                println!(
                    "{:<4} {:<24} {:<28} {:<8} {:<8} {:<3} {}",
                    number(p, "id"),
                    text(p, "consumerType"),
                    text(p, "name"),
                    enabled(boolean(p, "enabled")),
                    enabled(boolean(p, "requiresApproval")),
                    number(p, "priority"),
                    text(p, "updatedAt")
                );
            }
        }
        return Ok(());
    }
    if action == "create" {
        let f = crate::flags::parse(
            "approval create",
            args,
            &["consumer-type", "name", "conditions", "approver-spec"],
            &["enabled", "requires-approval"],
            false,
        );
        if f.get("consumer-type").is_empty() {
            return Err("--consumer-type is required".into());
        }
        if f.get("name").is_empty() {
            return Err("--name is required".into());
        }
        let body = serde_json::json!({"consumerType":f.get("consumer-type"),"name":f.get("name"),"enabled":!f.set("enabled")||f.boolean("enabled"),"conditions":json_arg(if f.set("conditions"){f.get("conditions")}else{"{}"},"marshal: error calling MarshalJSON for type json.RawMessage: ")?,"requiresApproval":!f.set("requires-approval")||f.boolean("requires-approval"),"approverSpec":json_arg(if f.set("approver-spec"){f.get("approver-spec")}else{"{}"},"marshal: error calling MarshalJSON for type json.RawMessage: ")?});
        let v = api.raw_json(
            "POST",
            path,
            raw_map(
                &body,
                &[
                    ("conditions", f.get("conditions")),
                    ("approverSpec", f.get("approver-spec")),
                ],
            )?
            .into_bytes(),
            true,
        )?;
        println!("Approval policy created: id={}", number(&v, "id"));
        return Ok(());
    }
    if action == "update" {
        let f = crate::flags::parse(
            "approval update",
            args,
            &["id", "name", "conditions", "approver-spec"],
            &["enabled", "requires-approval"],
            false,
        );
        let id = f.get("id").parse::<i64>().unwrap_or(0);
        if id == 0 {
            return Err("--id is required".into());
        }
        let mut body = serde_json::json!({});
        if !f.get("name").is_empty() {
            body["name"] = f.get("name").into();
        }
        for (k, out) in [
            ("enabled", "enabled"),
            ("requires-approval", "requiresApproval"),
        ] {
            if f.set(k) {
                body[out] = f.boolean(k).into();
            }
        }
        for (k, out) in [
            ("conditions", "conditions"),
            ("approver-spec", "approverSpec"),
        ] {
            if !f.get(k).is_empty() {
                body[out] = json_arg(
                    f.get(k),
                    "marshal: error calling MarshalJSON for type json.RawMessage: ",
                )?;
            }
        }
        api.raw_json(
            "PUT",
            &format!("{path}/{id}"),
            raw_map(
                &body,
                &[
                    ("conditions", f.get("conditions")),
                    ("approverSpec", f.get("approver-spec")),
                ],
            )?
            .into_bytes(),
            false,
        )?;
        println!("Approval policy {id} updated.");
        return Ok(());
    }
    if action == "delete" {
        let id = &need(args, 1, "usage: mailctl approval delete <id>")?[0];
        o.confirm(&format!("Delete approval policy {id}"))?;
        api.request("DELETE", &format!("{path}/{id}"), None, false)?;
        println!("Approval policy {id} deleted.");
        return Ok(());
    }
    if action == "reorder" {
        let f = crate::flags::parse("approval reorder", args, &["consumer-type"], &[], false);
        if f.get("consumer-type").is_empty() {
            return Err("--consumer-type is required".into());
        }
        need(
            &f.positional,
            1,
            "usage: mailctl approval reorder --consumer-type <ct> <id1> <id2> ...",
        )?;
        let ids = f
            .positional
            .iter()
            .map(|s| decimal(s, "ID"))
            .collect::<Result<Vec<_>, _>>()?;
        api.request(
            "POST",
            &format!("{path}/reorder"),
            Some(serde_json::json!({"consumerType":f.get("consumer-type"),"orderedIds":ids})),
            false,
        )?;
        println!("Approval policy order updated.");
        return Ok(());
    }
    if action == "export" {
        let f = crate::flags::parse("approval export", args, &["consumer-type"], &[], false);
        let (_, ordered) = wire_request(
            api,
            "[]approvalPolicy",
            "GET",
            &approval_path(f.get("consumer-type")),
            None,
            &[],
            0,
        )
        .map_err(ca_exit)?;
        wire_output(&Options::default(), &ordered);
        return Ok(());
    }
    if action == "diff" {
        let f = crate::flags::parse("", args, &["f"], &[], false);
        let desired = json_arg(&read_document(&f, true)?, "invalid JSON: ")?;
        let live = api.request("GET", path, None, true).map_err(ca_exit)?;
        let mut added = Vec::new();
        let mut changed = Vec::new();
        let mut removed = Vec::new();
        for want in array(&desired) {
            if let Some(have) = array(&live)
                .iter()
                .find(|h| approval_key(h) == approval_key(want))
            {
                if approval_changed(have, want) {
                    changed.push(text(want, "name").to_owned());
                }
            } else {
                added.push(text(want, "name").to_owned());
            }
        }
        for have in array(&live) {
            if !array(&desired)
                .iter()
                .any(|w| approval_key(w) == approval_key(have))
            {
                removed.push(text(have, "name").to_owned());
            }
        }
        #[derive(serde::Serialize)]
        struct Diff {
            drift: bool,
            added: Vec<String>,
            changed: Vec<String>,
            removed: Vec<String>,
        }
        let result = Diff {
            drift: !added.is_empty() || !changed.is_empty() || !removed.is_empty(),
            added,
            changed,
            removed,
        };
        Options {
            json: true,
            ..Options::default()
        }
        .typed(&result);
        if result.drift {
            return Err(Failure::from("changes present").exit(2));
        }
        return Ok(());
    }
    if action == "apply" {
        let f = crate::flags::parse("approval apply", args, &["f"], &[], false);
        let raw = read_document(&f, false)?;
        let desired = json_arg(&raw, "invalid JSON: ")?;
        let live = api.request("GET", path, None, true).map_err(ca_exit)?;
        let raw_entries: Option<Vec<Box<serde_json::value::RawValue>>> =
            serde_json::from_str(&raw).map_err(|e| format!("invalid JSON: {e}"))?;
        let mut created = 0;
        let mut updated = 0;
        let mut unchanged = 0;
        for (i, want) in array(&desired).iter().enumerate() {
            let have = array(&live)
                .iter()
                .find(|h| approval_key(h) == approval_key(want));
            if have.is_some_and(|h| !approval_changed(h, want)) {
                unchanged += 1;
                continue;
            }
            let mut body = serde_json::json!({"name":text(want,"name"),"enabled":boolean(want,"enabled"),"conditions":want["conditions"],"requiresApproval":boolean(want,"requiresApproval"),"approverSpec":want["approverSpec"]});
            let (method, url, verb) = if let Some(h) = have {
                updated += 1;
                ("PUT", format!("{path}/{}", number(h, "id")), "update")
            } else {
                created += 1;
                body["consumerType"] = text(want, "consumerType").into();
                ("POST", path.to_owned(), "create")
            };
            let entry = raw_entries.as_ref().unwrap()[i].get();
            let fields: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
                serde_json::from_str(entry).unwrap();
            let entries = fields
                .iter()
                .filter(|(k, _)| ["conditions", "approverSpec"].contains(&k.as_str()))
                .map(|(k, v)| (k.as_str(), v.get()))
                .collect::<Vec<_>>();
            api.raw_json(method, &url, raw_map(&body, &entries)?.into_bytes(), false)
                .map_err(|mut e| {
                    e.message = format!("{verb} {:?}: {e}", text(want, "name"));
                    ca_exit(e)
                })?;
        }
        println!("Apply complete: {created} created, {updated} updated, {unchanged} unchanged.");
        return Ok(());
    }
    if action == "audit" {
        let f = crate::flags::parse("approval audit", args, &["limit", "offset"], &[], false);
        let limit = if f.set("limit") {
            f.get("limit").parse::<i64>().unwrap_or(0)
        } else {
            50
        };
        let offset = f.get("offset").parse::<i64>().unwrap_or(0);
        let v = api.request(
            "GET",
            &format!("/admin/approval-requests/audit?limit={limit}&offset={offset}"),
            None,
            true,
        )?;
        if o.json {
            o.output(&v);
        } else if array(&v).is_empty() {
            println!("No approval requests.");
        } else {
            Options::default().list(&v);
        }
        return Ok(());
    }
    // approval actions
    Err(format!("unknown approval action: {action} (try: list, create, update, delete, reorder, export, apply, diff, audit)").into())
}

pub(super) fn wire_request(
    api: &Api,
    shape: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
    limit: u64,
) -> Result<(Value, String), Failure> {
    let (raw, _) = api.bytes(
        method,
        path,
        Some("application/json"),
        body.map(|v| crate::client::go_json(&v, false).into_bytes()),
        headers,
        limit,
    )?;
    wire_decode(shape, &raw)
}
pub(super) fn wire_decode(shape: &str, raw: &[u8]) -> Result<(Value, String), Failure> {
    let s = std::str::from_utf8(raw).map_err(|e| e.to_string())?;
    let ordered = crate::wire_b::json(shape, s)?;
    let mut value = serde_json::from_str(&ordered).unwrap();
    let original: Value = serde_json::from_slice(raw).unwrap();
    restore_empty_collections(&mut value, &original);
    Ok((value, ordered))
}
pub(super) fn wire_output(o: &Options, ordered: &str) {
    if !o.quiet {
        println!("{}", escape_json_text(ordered));
    }
}
pub(super) fn escape_json_text(s: &str) -> String {
    s.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn approval_key(v: &Value) -> String {
    format!("{}\0{}", text(v, "consumerType"), text(v, "name"))
}
fn approval_changed(have: &Value, want: &Value) -> bool {
    if boolean(have, "enabled") != boolean(want, "enabled")
        || boolean(have, "requiresApproval") != boolean(want, "requiresApproval")
    {
        return true;
    }
    for k in ["conditions", "approverSpec"] {
        let empty = serde_json::json!({});
        if have.get(k).unwrap_or(&empty) != want.get(k).unwrap_or(&empty) {
            return true;
        }
    }
    false
}

pub(super) fn credentials(cmd: &str, args: &[String]) -> i32 {
    if cmd == "login" && args.is_empty() {
        eprintln!("Usage: mailctl login <server-url>");
        return 1;
    }
    if cmd == "login" {
        return match login(&args[0]) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("Login failed: {e}");
                1
            }
        };
    }
    let path = crate::client::account_home().join(".mailctl/config.yaml");
    let cfg = match std::fs::read(&path) {
        Ok(raw) => crate::client::parse_config(&raw).ok(),
        Err(_) => Some(crate::client::Config::default()),
    };
    if let Some(mut cfg) = cfg {
        cfg.auth.token.clear();
        cfg.auth.refresh_token.clear();
        let _ = save_config(&cfg);
    }
    println!("Logged out.");
    0
}

fn login(server: &str) -> Result<(), Failure> {
    use std::io::{BufRead, Write};
    print!("Email: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let email = line.split_whitespace().next().unwrap_or("").to_owned();
    print!("Password: ");
    std::io::stdout().flush().ok();
    let password = terminal_password().map_err(|e| format!("read password: {e}"))?;
    println!();
    let api = Api::at_server(server)?;
    let v = api
        .request(
            "POST",
            "/auth/login",
            Some(serde_json::json!({"email":email,"password":password})),
            true,
        )
        .map_err(|e| format!("login failed: {e}"))?;
    let cfg = crate::client::Config {
        server: server.into(),
        auth: crate::client::Auth {
            mode: "jwt".into(),
            token: text(&v, "access_token").into(),
            refresh_token: text(&v, "refresh_token").into(),
            ..Default::default()
        },
    };
    save_config(&cfg)?;
    println!("Logged into {server}");
    Ok(())
}
fn terminal_password() -> Result<String, Failure> {
    use std::io::BufRead;
    // termios is local to the inherited terminal; the guard restores it on every return path.
    struct Restore(libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
            }
        }
    }
    let mut old = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, old.as_mut_ptr()) } != 0 {
        return Err(crate::flags::go_io_error(&std::io::Error::last_os_error())
            .replace(
                "Inappropriate ioctl for device (os error 25)",
                "inappropriate ioctl for device",
            )
            .into());
    }
    let old = unsafe { old.assume_init() };
    let _restore = Restore(old);
    let mut state = old;
    state.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &state) } != 0 {
        return Err(std::io::Error::last_os_error().to_string().into());
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}
fn yaml_scalar(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if raw.is_empty()
        || raw.trim() != raw
        || raw.contains(['\r', '\n', ':', '#', '[', ']', '{', '}', '"', '\\'])
            && !raw.starts_with("http://")
            && !raw.starts_with("https://")
        || [
            "y", "yes", "n", "no", "true", "false", "on", "off", "null", "~",
        ]
        .contains(&lower.as_str())
        || raw.parse::<f64>().is_ok()
    {
        serde_json::to_string(raw).unwrap()
    } else {
        raw.into()
    }
}
fn save_config(cfg: &crate::client::Config) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt;
    let path = crate::client::account_home().join(".mailctl/config.yaml");
    let mut raw = format!(
        "server: {}\nauth:\n    mode: {}\n",
        yaml_scalar(&cfg.server),
        yaml_scalar(&cfg.auth.mode)
    );
    for (k, v) in [
        ("api_key", &cfg.auth.api_key),
        ("token", &cfg.auth.token),
        ("refresh_token", &cfg.auth.refresh_token),
    ] {
        if !v.is_empty() {
            raw.push_str(&format!("    {k}: {}\n", yaml_scalar(v)));
        }
    }
    private_write(&path, raw.as_bytes(), 0o600)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn role(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    let path = "/admin/roles";
    if action == "list" {
        let (v, ordered) = wire_request(api, "[]roleRow", "GET", path, None, &[], 0)?;
        if o.json {
            wire_output(o, &ordered);
        } else if array(&v).is_empty() {
            println!("No roles defined.");
        } else {
            println!(
                "{:<5} {:<25} {:<8} {:<8} Permissions",
                "ID", "Name", "Builtin", "Members"
            );
            for p in array(&v) {
                println!(
                    "{:<5} {:<25} {:<8} {:<8} {}",
                    number(p, "id"),
                    text(p, "name"),
                    if boolean(p, "isBuiltin") { "yes" } else { "no" },
                    number(p, "memberCount"),
                    array(&p["permissions"])
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
        }
        return Ok(());
    }
    if action == "create" {
        let f = crate::flags::parse(
            "role create",
            args,
            &["name", "desc", "permissions", "reason", "domain-scope"],
            &[],
            false,
        );
        if f.get("name").is_empty() {
            return Err("--name is required".into());
        }
        if f.get("permissions").is_empty() {
            return Err("--permissions is required".into());
        }
        role_reason(f.get("reason"), "create")?;
        let mut body = serde_json::json!({"name":f.get("name"),"description":f.get("desc"),"permissions":csv_value(f.get("permissions"))});
        let domain = f.get("domain-scope").parse::<i64>().unwrap_or(0);
        if domain > 0 {
            body["domainScope"] = domain.into();
        }
        let v = role_request(api, "POST", path, Some(body), true, f.get("reason"))?;
        if o.json {
            #[derive(serde::Serialize)]
            struct Created {
                id: i64,
            }
            o.typed(&Created {
                id: number(&v, "id"),
            });
        } else {
            println!("Role created: id={}", number(&v, "id"));
        }
        return Ok(());
    }
    if action == "update" {
        let f = crate::flags::parse(
            "role update",
            args,
            &[
                "id",
                "name",
                "desc",
                "permissions",
                "reason",
                "domain-scope",
                "sod-class",
            ],
            &[],
            false,
        );
        let id = f.get("id").parse::<i64>().unwrap_or(0);
        if id == 0 {
            return Err("--id is required".into());
        }
        role_reason(f.get("reason"), "update")?;
        let mut body = serde_json::json!({});
        for (k, out) in [
            ("name", "name"),
            ("desc", "description"),
            ("sod-class", "sodClass"),
        ] {
            if f.set(k) {
                body[out] = f.get(k).into();
            }
        }
        if f.set("permissions") {
            body["permissions"] = csv_value(f.get("permissions"));
        }
        if f.set("domain-scope") {
            body["domainScope"] = f.get("domain-scope").parse::<i64>().unwrap_or(0).into();
        }
        if body.as_object().unwrap().is_empty() {
            return Err("no fields to update (set --name, --desc, --permissions, --domain-scope, or --sod-class)".into());
        }
        role_request(
            api,
            "PUT",
            &format!("{path}/{id}"),
            Some(body),
            false,
            f.get("reason"),
        )?;
        println!("Role {id} updated.");
        return Ok(());
    }
    if action == "delete" {
        let id = need(args, 1, "usage: mailctl role delete <id> --reason <r>")?
            .first()
            .filter(|s| !s.starts_with('-'))
            .ok_or("usage: mailctl role delete <id> --reason <r>")?;
        let f = crate::flags::parse("role delete", &args[1..], &["reason"], &[], false);
        role_reason(f.get("reason"), "delete")?;
        o.confirm(&format!("Delete role {id}"))?;
        role_request(
            api,
            "DELETE",
            &format!("{path}/{id}"),
            None,
            false,
            f.get("reason"),
        )?;
        println!("Role {id} deleted.");
        return Ok(());
    }
    if action == "grant" {
        let usage =
            "usage: mailctl role grant <email> --role <name> --reason <r> [--expires <RFC3339>]";
        let email = need(args, 1, usage)?
            .first()
            .filter(|s| !s.starts_with('-'))
            .ok_or(usage)?;
        let f = crate::flags::parse(
            "role grant",
            &args[1..],
            &["role", "reason", "expires"],
            &[],
            false,
        );
        if f.get("role").is_empty() {
            return Err("--role is required".into());
        }
        role_reason(f.get("reason"), "grant")?;
        let roles = api.request("GET", path, None, true)?;
        let r = array(&roles)
            .iter()
            .find(|r| text(r, "name") == f.get("role"))
            .ok_or_else(|| format!("no role found with name {:?}", f.get("role")))?;
        let uid = resolve_user(api, email)?;
        if boolean(r, "isBuiltin") {
            o.confirm(&format!(
                "Grant privileged (built-in) role {:?} to {email}",
                text(r, "name")
            ))?;
        }
        let id = number(r, "id");
        let mut body = serde_json::json!({"userId":uid});
        if !f.get("expires").is_empty() {
            body["expiresAt"] = f.get("expires").into();
        }
        role_request(
            api,
            "POST",
            &format!("{path}/{id}/members"),
            Some(body),
            false,
            f.get("reason"),
        )?;
        println!("Granted role {:?} to {email}.", text(r, "name"));
        return Ok(());
    }
    if action == "revoke" {
        let usage = "usage: mailctl role revoke <email> --role <name> --reason <r>";
        let email = need(args, 1, usage)?
            .first()
            .filter(|s| !s.starts_with('-'))
            .ok_or(usage)?;
        let f = crate::flags::parse("role revoke", &args[1..], &["role", "reason"], &[], false);
        if f.get("role").is_empty() {
            return Err("--role is required".into());
        }
        role_reason(f.get("reason"), "revoke")?;
        let roles = api.request("GET", path, None, true)?;
        let r = array(&roles)
            .iter()
            .find(|r| text(r, "name") == f.get("role"))
            .ok_or_else(|| format!("no role found with name {:?}", f.get("role")))?;
        let uid = resolve_user(api, email)?;
        if boolean(r, "isBuiltin") {
            o.confirm(&format!(
                "Revoke privileged (built-in) role {:?} from {email}",
                text(r, "name")
            ))?;
        }
        let id = number(r, "id");
        role_request(
            api,
            "DELETE",
            &format!("{path}/{id}/members/{uid}"),
            None,
            false,
            f.get("reason"),
        )?;
        println!("Revoked role {:?} from {email}.", text(r, "name"));
        return Ok(());
    }
    if action == "export" {
        let roles = api.request("GET", path, None, true)?;
        let mut entries = Vec::new();
        for r in array(&roles) {
            let v = api.request("GET", &format!("{path}/{}", number(r, "id")), None, true)?;
            let mut emails = array(&v["members"])
                .iter()
                .map(|m| text(m, "userEmail").to_owned())
                .collect::<Vec<_>>();
            emails.sort();
            let mut e = serde_json::json!({"name":text(r,"name"),"description":text(r,"description"),"permissions":r["permissions"],"isBuiltin":boolean(r,"isBuiltin"),"members":emails});
            if !r["domainScope"].is_null() {
                e["domainScope"] = r["domainScope"].clone();
            }
            entries.push(e);
        }
        let s = crate::wire_b::json(
            "roleExport",
            &crate::client::go_json(&serde_json::json!({"roles":entries}), false),
        )?;
        wire_output(&Options::default(), &s);
        return Ok(());
    }
    if action == "diff" || action == "apply" {
        let apply = action == "apply";
        let f = crate::flags::parse(
            &format!("role {action}"),
            args,
            &["f", "reason"],
            &["prune"],
            false,
        );
        if apply {
            role_reason(f.get("reason"), "apply")?;
        }
        let raw = read_document(&f, false)?;
        let doc = json_arg(&raw, "invalid JSON: ")?;
        let changed = reconcile_roles(
            api,
            &doc,
            apply,
            f.boolean("prune"),
            if apply { f.get("reason") } else { "" },
        )?;
        if apply {
            println!(
                "{}",
                if changed {
                    "Apply complete."
                } else {
                    "No changes; roles already match the document."
                }
            );
        } else if changed {
            return Err(Failure::from("changes present").exit(2));
        } else {
            println!("No drift.");
        }
        return Ok(());
    }
    // role apply shares the declarative reconcile seam with diff.
    // role actions
    Err(format!("unknown role action: {action} (try: list, create, update, delete, grant, revoke, export, apply, diff)").into())
}

fn role_reason(reason: &str, action: &str) -> Result<(), Failure> {
    if reason.trim().is_empty() {
        Err(format!("--reason is required for role {action} (audit-hardened deployments reject role mutations without an audit reason)").into())
    } else {
        Ok(())
    }
}
pub(super) fn csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
fn csv_value(raw: &str) -> Value {
    let v = csv(raw);
    if v.is_empty() {
        Value::Null
    } else {
        serde_json::json!(v)
    }
}
fn role_request(
    api: &Api,
    method: &str,
    path: &str,
    body: Option<Value>,
    decode: bool,
    reason: &str,
) -> Result<Value, Failure> {
    let headers = if reason.is_empty() {
        Vec::new()
    } else {
        vec![("X-Audit-Reason", reason.into())]
    };
    api.with_headers(method, path, body, decode, &headers, 0)
}

fn resolve_user(api: &Api, email: &str) -> Result<i64, Failure> {
    if email.is_empty() {
        return Err("email is required".into());
    }
    let users = api.request("GET", "/admin/users", None, true)?;
    array(&users)
        .iter()
        .find(|u| text(u, "email") == email)
        .map(|u| number(u, "id"))
        .ok_or_else(|| format!("no user found with email {email:?}").into())
}

fn reconcile_roles(
    api: &Api,
    doc: &Value,
    apply: bool,
    prune: bool,
    reason: &str,
) -> Result<bool, Failure> {
    let live = role_request(api, "GET", "/admin/roles", None, true, reason)?;
    let users = role_request(api, "GET", "/admin/users", None, true, reason)?;
    let mut changed = false;
    for want in array(&doc["roles"]) {
        let name = text(want, "name");
        let have = array(&live).iter().find(|r| text(r, "name") == name);
        let mut id = have.map(|r| number(r, "id")).unwrap_or(0);
        if have.is_none() {
            changed = true;
            if boolean(want, "isBuiltin") {
                println!("~ skip built-in role {name:?} (absent; built-ins are server-seeded)");
                continue;
            }
            if apply {
                let mut body = serde_json::json!({"name":name,"description":text(want,"description"),"permissions":want["permissions"]});
                if number(want, "domainScope") > 0 {
                    body["domainScope"] = want["domainScope"].clone();
                }
                let v = role_request(api, "POST", "/admin/roles", Some(body), true, reason)?;
                id = number(&v, "id");
                println!("+ created role {name:?} (id={id})");
            } else {
                println!("+ create role {name:?}");
            }
        } else if let Some(have) = have {
            let mut wp = array(&want["permissions"])
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>();
            let mut hp = array(&have["permissions"])
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>();
            wp.sort();
            hp.sort();
            if !boolean(have, "isBuiltin")
                && (text(want, "description") != text(have, "description")
                    || wp != hp
                    || want["domainScope"] != have["domainScope"])
            {
                changed = true;
                if apply {
                    role_request(
                        api,
                        "PUT",
                        &format!("/admin/roles/{id}"),
                        Some(
                            serde_json::json!({"name":name,"description":text(want,"description"),"permissions":want["permissions"]}),
                        ),
                        false,
                        reason,
                    )?;
                    println!("~ updated role {name:?}");
                } else {
                    println!("~ update role {name:?}");
                }
            }
        }
        let members = if have.is_some() {
            role_request(
                api,
                "GET",
                &format!("/admin/roles/{id}"),
                None,
                true,
                reason,
            )?
        } else {
            Value::Null
        };
        for e in array(&want["members"]) {
            let email = e.as_str().unwrap_or("");
            if array(&members["members"])
                .iter()
                .any(|m| text(m, "userEmail") == email)
            {
                continue;
            }
            changed = true;
            let uid = array(&users)
                .iter()
                .find(|u| text(u, "email") == email)
                .map(|u| number(u, "id"))
                .ok_or_else(|| format!("role {name:?}: no user with email {email:?}"))?;
            if apply {
                if id == 0 {
                    return Err(format!(
                        "role {name:?}: cannot grant members to a role that failed to create"
                    )
                    .into());
                }
                role_request(
                    api,
                    "POST",
                    &format!("/admin/roles/{id}/members"),
                    Some(serde_json::json!({"userId":uid})),
                    false,
                    reason,
                )?;
                println!("+ granted {email} -> {name:?}");
            } else {
                println!("+ grant {email} -> {name:?}");
            }
        }
        if prune {
            for member in array(&members["members"]) {
                let email = text(member, "userEmail");
                if array(&want["members"])
                    .iter()
                    .any(|e| e.as_str() == Some(email))
                {
                    continue;
                }
                changed = true;
                if apply {
                    role_request(
                        api,
                        "DELETE",
                        &format!("/admin/roles/{id}/members/{}", number(member, "userId")),
                        None,
                        false,
                        reason,
                    )?;
                    println!("- revoked {email} from {name:?}");
                } else {
                    println!("- revoke {email} from {name:?}");
                }
            }
        }
    }
    if prune {
        for r in array(&live) {
            let name = text(r, "name");
            if boolean(r, "isBuiltin")
                || array(&doc["roles"]).iter().any(|w| text(w, "name") == name)
            {
                continue;
            }
            changed = true;
            if apply {
                role_request(
                    api,
                    "DELETE",
                    &format!("/admin/roles/{}", number(r, "id")),
                    None,
                    false,
                    reason,
                )?;
                println!("- deleted role {name:?}");
            } else {
                println!("- delete role {name:?}");
            }
        }
    }
    Ok(changed)
}

fn office(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "status" {
        if !args.is_empty() {
            return Err("usage: mailctl office status".into());
        }
        let v = api.with_headers("GET", "/admin/office", None, true, &[], 2 << 20)?;
        o.output(&v);
        return Ok(());
    }
    if action == "configure" {
        let f = crate::flags::parse(
            "office configure",
            args,
            &[
                "provider",
                "generation",
                "profile",
                "entitlement-state",
                "build-id",
                "discovery-url",
                "wopi-base-url",
                "editor-url",
                "allow-hosts",
                "allow-cidrs",
                "reason",
            ],
            &[],
            false,
        );
        let generation = f.get("generation").parse::<i64>().unwrap_or(-1);
        if !f.positional.is_empty()
            || generation < 0
            || ["discovery-url", "wopi-base-url", "editor-url"]
                .iter()
                .any(|k| f.get(k).is_empty())
        {
            return Err("usage: mailctl office configure --generation N --discovery-url URL --wopi-base-url URL --editor-url URL --reason TEXT [--profile existing-provider]".into());
        }
        let provider = flag_default(&f, "provider", "collabora");
        let profile = flag_default(&f, "profile", "existing-provider");
        let build = if f.get("build-id").is_empty() {
            Value::Null
        } else {
            f.get("build-id").into()
        };
        let body = serde_json::json!({"expectedGeneration":generation,"profile":profile,"entitlementState":flag_default(&f,"entitlement-state","unknown"),"buildId":build,"config":{"proofDiscoveryUrl":f.get("discovery-url"),"wopiPublicBaseUrl":f.get("wopi-base-url"),"editorUrl":f.get("editor-url"),"profile":profile,"privateAllowHosts":csv(f.get("allow-hosts")),"privateAllowCidrs":csv(f.get("allow-cidrs"))}});
        return office_mutation(
            api,
            o,
            "PUT",
            &format!("/admin/office/providers/{provider}"),
            f.get("reason"),
            "",
            body,
        );
    }
    if action == "qualify" {
        let f = crate::flags::parse(
            "office qualify",
            args,
            &[
                "provider",
                "generation",
                "synthetic-receipt",
                "build-digest",
                "route-revision",
                "reason",
            ],
            &[],
            false,
        );
        let generation = f.get("generation").parse::<i64>().unwrap_or(0);
        let receipt = f.get("synthetic-receipt").parse::<i64>().unwrap_or(0);
        let route = flag_default(&f, "route-revision", "1")
            .parse::<i64>()
            .unwrap_or(0);
        if !f.positional.is_empty() || generation <= 0 || receipt <= 0 || route <= 0 {
            return Err("usage: mailctl office qualify --generation N --synthetic-receipt ID --reason TEXT [--build-digest sha256:...]".into());
        }
        return office_mutation(
            api,
            o,
            "POST",
            &format!(
                "/admin/office/providers/{}/qualify",
                flag_default(&f, "provider", "collabora")
            ),
            f.get("reason"),
            "",
            serde_json::json!({"expectedGeneration":generation,"syntheticReceiptId":receipt,"buildDigest":f.get("build-digest"),"routeRevision":route}),
        );
    }
    if action == "activate" {
        let f = crate::flags::parse(
            "office activate",
            args,
            &["provider", "generation", "qualification", "scope", "reason"],
            &[],
            false,
        );
        let generation = f.get("generation").parse::<i64>().unwrap_or(0);
        if !f.positional.is_empty() || generation <= 0 {
            return Err("usage: mailctl office activate --generation N --qualification UUID --scope JSON --reason TEXT --yes".into());
        }
        if uuid(f.get("qualification")).is_none() {
            return Err("--qualification must be a UUID".into());
        }
        if !o.yes {
            return Err("office activation changes document routing; re-run with --yes".into());
        }
        let scope = json_object(
            flag_default(&f, "scope", "{}"),
            "--scope must be a JSON object: ",
        )?;
        return office_mutation(
            api,
            o,
            "POST",
            &format!(
                "/admin/office/providers/{}/activate",
                flag_default(&f, "provider", "collabora")
            ),
            f.get("reason"),
            "",
            serde_json::json!({"expectedGeneration":generation,"qualificationId":f.get("qualification"),"scope":scope}),
        );
    }
    if action == "install" {
        let f = crate::flags::parse(
            "office install",
            args,
            &[
                "provider",
                "generation",
                "profile",
                "ingress",
                "reason",
                "idempotency-key",
            ],
            &[],
            false,
        );
        let generation = f.get("generation").parse::<i64>().unwrap_or(0);
        if !f.positional.is_empty() || generation <= 0 {
            return Err("usage: mailctl office install --generation N --profile managed-customer-proxy --ingress JSON --reason TEXT --yes".into());
        }
        if !o.yes {
            return Err(
                "managed CODE installation changes the local container runtime; re-run with --yes"
                    .into(),
            );
        }
        let key = if f.get("idempotency-key").is_empty() {
            new_uuid()?
        } else {
            f.get("idempotency-key").into()
        };
        if uuid(&key).is_none_or(|s| s != key) {
            return Err("--idempotency-key must be one canonical UUID".into());
        }
        let ingress = json_object(
            flag_default(&f, "ingress", "{}"),
            "--ingress must be a JSON object: ",
        )?;
        return office_mutation(
            api,
            o,
            "POST",
            "/admin/apps/collabora-code/operations",
            f.get("reason"),
            &key,
            serde_json::json!({"kind":"install","providerId":flag_default(&f,"provider","collabora"),"expectedProviderGeneration":generation,"idempotencyKey":key,"request":{"profile":flag_default(&f,"profile","managed-customer-proxy"),"ingress":ingress,"catalogRevision":1}}),
        );
    }
    if action == "recover" {
        let f = crate::flags::parse(
            "office recover",
            args,
            &["operation", "generation", "reason"],
            &[],
            false,
        );
        let generation = f.get("generation").parse::<i64>().unwrap_or(0);
        if !f.positional.is_empty() || generation <= 0 {
            return Err(
                "usage: mailctl office recover --operation UUID --generation N --reason TEXT --yes"
                    .into(),
            );
        }
        let operation = f.get("operation");
        if uuid(operation).is_none_or(|s| s != operation) {
            return Err("--operation must be one canonical UUID".into());
        }
        if !o.yes {
            return Err(
                "managed CODE recovery re-inventories local runtime state; re-run with --yes"
                    .into(),
            );
        }
        return office_mutation(
            api,
            o,
            "POST",
            &format!("/admin/apps/collabora-code/operations/{operation}/recover"),
            f.get("reason"),
            "",
            serde_json::json!({"expectedGeneration":generation}),
        );
    }
    if action == "doctor" || action == "diagnostics" {
        return office_report(api, o, action, args);
    }
    // office actions
    Err(format!("unknown office action: {action} (try: doctor, diagnostics, status, configure, qualify, activate, install, recover)").into())
}

pub(super) fn flag_default<'a>(f: &'a crate::flags::Flags, key: &str, default: &'a str) -> &'a str {
    if f.set(key) {
        f.get(key)
    } else {
        default
    }
}
fn office_mutation(
    api: &Api,
    o: &Options,
    method: &str,
    path: &str,
    reason: &str,
    key: &str,
    body: Value,
) -> Result<(), Failure> {
    safe_reason(reason)?;
    let mut headers = vec![("X-Audit-Reason", reason.into())];
    if !key.is_empty() {
        headers.push(("Idempotency-Key", key.into()));
    }
    let v = api.with_headers(method, path, Some(body), true, &headers, 2 << 20)?;
    o.output(&v);
    Ok(())
}

fn json_object(raw: &str, prefix: &str) -> Result<Value, Failure> {
    let v = json_arg(raw, prefix)?;
    if !v.is_object() && !v.is_null() {
        let ty = if v.is_array() {
            "array"
        } else if v.is_number() {
            "number"
        } else if v.is_boolean() {
            "bool"
        } else {
            "string"
        };
        return Err(format!(
            "{prefix}json: cannot unmarshal {ty} into Go value of type map[string]interface {{}}"
        )
        .into());
    }
    Ok(v)
}
fn office_report(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    let f = crate::flags::parse(
        &format!("office {action}"),
        args,
        &[],
        &["json", "quiet"],
        false,
    );
    let local = Options {
        json: if f.set("json") {
            f.boolean("json")
        } else {
            o.json
        },
        quiet: if f.set("quiet") {
            f.boolean("quiet")
        } else {
            o.quiet
        },
        yes: o.yes,
    };
    if !f.positional.is_empty() {
        return Err(format!("usage: mailctl office {action} [--json]").into());
    }
    let o = &local;
    let rows = api.with_headers("GET", "/admin/features", None, true, &[], 1 << 20)?;
    let specs = [
        (
            "feature.office_editing",
            "Office online editing",
            "configure only after an approved Office provider and Drive policy are ready",
        ),
        (
            "feature.office_local_open",
            "Office local open",
            "configure only after the controlled desktop application policy is ready",
        ),
        (
            "feature.drive_history",
            "Drive History",
            "configure only after Drive History retention and access policy are ready",
        ),
    ];
    let mut statuses = Vec::new();
    let mut missing = 0;
    let mut blockers = 0;
    let drive = array(&rows)
        .iter()
        .rev()
        .find(|r| text(r, "key") == "feature.drive");
    let drive_off = drive.is_some_and(|r| {
        !r["gatewayEffective"]
            .as_bool()
            .unwrap_or(boolean(r, "enabled"))
    });
    for (key, label, configuration_hint) in specs {
        let row = array(&rows).iter().rev().find(|r| text(r, "key") == key);
        let empty = Value::Null;
        let r = row.unwrap_or(&empty);
        let present = row.is_some();
        let default = boolean(r, "defaultEnabled");
        let effective = r["gatewayEffective"]
            .as_bool()
            .unwrap_or(boolean(r, "enabled"));
        let configured = !r["storedEnabled"].is_null();
        let source = if text(r, "gatewaySource").is_empty() {
            "unknown"
        } else {
            text(r, "gatewaySource")
        };
        let dependencies = if array(&r["dependencies"]).is_empty() {
            serde_json::json!(["feature.drive"])
        } else {
            r["dependencies"].clone()
        };
        let state = if !present {
            missing += 1;
            "missing"
        } else if effective {
            "on"
        } else {
            "off"
        };
        if effective
            && drive_off
            && array(&dependencies)
                .iter()
                .any(|v| v.as_str() == Some("feature.drive"))
        {
            blockers += 1;
        }
        let hint = if !present {
            "not reported by this server; upgrade the server before configuring this flag"
                .to_owned()
        } else if !effective && !configured && !default {
            format!("default-OFF; configure with 'mailctl feature set {key} on' only after the required policy and evidence are ready")
        } else if !effective && configured {
            format!("configured OFF; run 'mailctl feature set {key} on' only after the required policy and evidence are ready")
        } else {
            configuration_hint.into()
        };
        let mut status = serde_json::json!({"key":key,"label":label,"present":present,"state":state,"enabled":boolean(r,"enabled"),"defaultEnabled":default,"defaultOff":!default,"configured":configured,"gatewayEffective":effective,"gatewaySource":source,"dependencies":dependencies,"confirmationRequired":boolean(r,"confirmationRequired"),"hint":hint});
        for k in [
            "registryMode",
            "classification",
            "changeMode",
            "disableBehavior",
        ] {
            if !text(r, k).is_empty() {
                status[k] = r[k].clone();
            }
        }
        statuses.push(status);
    }
    let doctor = action == "doctor";
    let mut hints = Vec::new();
    if missing > 0 {
        hints.push("The server must expose all three Office/History flags before this command can verify configuration.".to_owned());
    }
    for s in &statuses {
        if !text(s, "hint").is_empty() {
            hints.push(format!("{}: {}", text(s, "key"), text(s, "hint")));
        }
    }
    if statuses.iter().all(|s| boolean(s, "defaultOff")) {
        hints.push("All Office and Drive History capabilities are default-OFF; no capability is enabled until explicitly configured.".into());
    }
    if blockers > 0 {
        hints.push("Enabled Office/History capabilities require feature.drive to be enabled before admission can succeed.".into());
    }
    if o.json {
        let doc = serde_json::json!({"source":"admin feature registry","endpoint":"/admin/features","flags":statuses,"hints":hints,"status":if missing>0{"partial"}else{"ok"}});
        let ordered = crate::wire_b::json(
            if doctor {
                "officeDoctorReport"
            } else {
                "officeDiagnosticsReport"
            },
            &crate::client::go_json(&doc, false),
        )?;
        wire_output(o, &ordered);
    } else if !o.quiet {
        if doctor {
            println!("Office doctor (sanitized feature status)\nSource: admin feature registry  Endpoint: /admin/features");
            for s in &statuses {
                print!(
                    "  {:<25} {:<7} default {}",
                    text(s, "key"),
                    text(s, "state").to_uppercase(),
                    if boolean(s, "defaultOff") {
                        "OFF"
                    } else {
                        "ON"
                    }
                );
                print!(
                    " {}",
                    if boolean(s, "configured") {
                        "configured"
                    } else {
                        "registry-default"
                    }
                );
                if !boolean(s, "present") {
                    print!(" missing");
                }
                println!();
                if text(s, "gatewaySource") != "unknown" {
                    println!(
                        "      gateway={} source={}",
                        on_off(boolean(s, "gatewayEffective")),
                        text(s, "gatewaySource")
                    );
                }
                if !array(&s["dependencies"]).is_empty() {
                    println!(
                        "      requires={}",
                        string_array(&s["dependencies"]).join(",")
                    );
                }
                if !text(s, "hint").is_empty() {
                    println!("      hint: {}", text(s, "hint"));
                }
            }
            for h in hints {
                println!("Hint: {h}");
            }
        } else {
            println!("Office diagnostics (sanitized server status)\nSource: admin feature registry  Endpoint: /admin/features  Status: {}",if missing>0{"partial"}else{"ok"});
            for s in &statuses {
                println!(
                    "  {:<25} {:<7} enabled={} default={} configured={} gateway={} source={}",
                    text(s, "key"),
                    text(s, "state"),
                    on_off(boolean(s, "enabled")),
                    on_off(boolean(s, "defaultEnabled")),
                    boolean(s, "configured"),
                    on_off(boolean(s, "gatewayEffective")),
                    text(s, "gatewaySource")
                );
                if !array(&s["dependencies"]).is_empty() {
                    println!(
                        "      requires={}",
                        string_array(&s["dependencies"]).join(",")
                    );
                }
            }
        }
    }
    if doctor && missing > 0 {
        return Err(format!("office doctor: server did not report {missing} required Office/History feature flag(s)").into());
    }
    if doctor && blockers > 0 {
        return Err(
            "office doctor: one or more enabled flags have disabled Drive dependencies".into(),
        );
    }
    Ok(())
}
fn string_array(v: &Value) -> Vec<&str> {
    array(v).iter().filter_map(Value::as_str).collect()
}
fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

// Go's MarshalIndent formats embedded RawMessage values too; serde emits them verbatim.
pub(super) fn ordered_pretty(raw: &str) -> String {
    let compact = compact_json(raw).expect("serialized JSON is valid");
    let chars = compact.chars().collect::<Vec<_>>();
    let mut out = String::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (i, &c) in chars.iter().enumerate() {
        if quoted {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => {
                quoted = true;
                out.push(c);
            }
            '{' | '[' => {
                out.push(c);
                depth += 1;
                if chars.get(i + 1).is_some_and(|n| *n != '}' && *n != ']') {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth));
                }
            }
            '}' | ']' => {
                depth -= 1;
                if i > 0 && chars[i - 1] != '{' && chars[i - 1] != '[' {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth));
                }
                out.push(c);
            }
            ',' => {
                out.push_str(",\n");
                out.push_str(&"  ".repeat(depth));
            }
            ':' => out.push_str(": "),
            _ => out.push(c),
        }
    }
    out
}

fn restore_empty_collections(value: &mut Value, original: &Value) {
    match (value, original) {
        (Value::Object(out), Value::Object(input)) => {
            for (k, v) in input {
                if let Some(target) = out.get_mut(k) {
                    restore_empty_collections(target, v);
                } else if v.as_array().is_some_and(Vec::is_empty)
                    || v.as_object().is_some_and(serde_json::Map::is_empty)
                {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
        (Value::Array(out), Value::Array(input)) => {
            for (a, b) in out.iter_mut().zip(input) {
                restore_empty_collections(a, b);
            }
        }
        _ => {}
    }
}
