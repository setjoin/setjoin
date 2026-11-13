//! Frozen-Go operator CLI. The process boundary is the compatibility contract.
mod backup;
mod ca_schema;
mod client;
mod direct;
mod entitlement;
mod exchange;
mod exchange_a0;
mod flags;
mod identity;
mod identity_checks;
mod identity_source_doc;
mod models;
mod offline;
mod part_b;
mod wire_b;
use client::{go_json_generic, go_value, Api};
use serde_json::Value;

pub fn run(args: Vec<String>) -> i32 {
    let Some(cmd) = args.first() else {
        eprintln!("Usage: mailctl <command> [args...]\nRun 'mailctl help' for available commands.");
        return 1;
    };
    if matches!(cmd.as_str(), "help" | "-h" | "--help") {
        print!("{}", include_str!("help.txt"));
        return 0;
    }
    let usage: Value = serde_json::from_str(include_str!("usage.json")).unwrap();
    let Some(usage) = usage.get(cmd).and_then(Value::as_str) else {
        eprintln!("Unknown command: {cmd}\nRun 'mailctl help' for available commands.");
        return 1;
    };
    if matches!(cmd.as_str(), "login" | "logout") {
        return part_b::credentials(cmd, &args[1..]);
    }
    let action = args.get(1).map(String::as_str).unwrap_or("");
    if matches!(action, "help" | "-h" | "--help") || (action.is_empty() && cmd != "version") {
        println!("Usage: mailctl {usage}\n\nFlags (all subcommands): --json, --quiet, --yes/-y");
        return 0;
    }
    if cmd == "version" {
        println!("mailctl v1.0.0");
        return 0;
    }
    if matches!(
        cmd.as_str(),
        "schema" | "scim" | "bootstrap-admin" | "sources" | "smime" | "push"
    ) {
        return direct::run(cmd, action, &args[2..]);
    }
    if matches!(
        cmd.as_str(),
        "dane" | "exchange" | "exchange-a0" | "entitlement"
    ) {
        return match offline::run(cmd, action, &args[2..]) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("Error: {e}");
                e.code
            }
        };
    }
    if matches!(cmd.as_str(), "backup-db" | "restore") {
        return match backup::run(cmd, &args[1..]) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("Error: {e}");
                e.code
            }
        };
    }
    let api = match Api::load() {
        Ok(api) => api,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let (options, rest) = Options::parse(&args[2..]);
    if cmd == "backup" {
        return match backup::api(&api, &options, action, rest) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("Error: {e}");
                e.code
            }
        };
    }
    if part_b::owns(cmd) {
        return match part_b::execute(&api, &options, cmd, action, rest) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("Error: {e}");
                e.code
            }
        };
    }
    match execute(&api, &options, cmd, action, rest) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

fn execute(
    api: &Api,
    options: &Options,
    cmd: &str,
    action: &str,
    args: &[String],
) -> Result<(), String> {
    if cmd == "backup" && action == "list" {
        options.list(&api.call("GET", "/admin/system/backup/list", None, true)?);
        return Ok(());
    }
    if cmd == "backup" && action == "run" {
        api.call("POST", "/admin/system/backup", None, true)?;
        return Ok(());
    }
    if cmd == "health" {
        let value = api.call("GET", "/admin/health", None, true)?;
        options.output(&value);
        return Ok(());
    }
    if cmd == "domain" && action == "add" {
        let name = args.first().ok_or("usage: mailctl domain add <name>")?;
        let v = api.call(
            "POST",
            "/admin/domains",
            Some(serde_json::json!({"name":name})),
            true,
        )?;
        if options.json {
            options.output(&v);
        } else {
            println!("Domain {name} added (id {}).", go_value(&v["id"]));
        }
        return Ok(());
    }
    if cmd == "domain" && action == "list" {
        options.list(&api.call("GET", "/admin/domains", None, true)?);
        return Ok(());
    }
    if cmd == "domain" && action == "delete" {
        let name = args.first().ok_or("usage: mailctl domain delete <name>")?;
        options.confirm(&format!("Delete domain {name}"))?;
        api.call(
            "DELETE",
            &format!("/admin/domains?name={name}"),
            None,
            false,
        )?;
        return Ok(());
    }
    if cmd == "config" && action == "list" {
        let v = api.call("GET", "/admin/system/config", None, true)?;
        options.list(&v);
        return Ok(());
    }
    if cmd == "config" && action == "get" {
        let v = api.call(
            "GET",
            &format!(
                "/admin/system/config/{}",
                args.first().ok_or("config key required")?
            ),
            None,
            true,
        )?;
        options.output(&v);
        return Ok(());
    }
    if cmd == "migration" && action == "list" {
        let v = api.call("GET", "/admin/migration/jobs", None, true)?;
        options.list(&v);
        return Ok(());
    }
    if cmd == "migration" && action == "status" {
        let v = api.call(
            "GET",
            &format!(
                "/admin/migration/jobs/{}",
                args.first().ok_or("job ID required")?
            ),
            None,
            true,
        )?;
        options.output(&v);
        return Ok(());
    }
    if cmd == "migration" && action == "cancel" {
        let v = api.call(
            "POST",
            &format!(
                "/admin/migration/jobs/{}/cancel",
                args.first().ok_or("job ID required")?
            ),
            None,
            false,
        )?;
        let _ = v;
        return Ok(());
    }
    if cmd == "storage" && action == "status" {
        let v = api.call("GET", "/admin/storage/status", None, true)?;
        options.output(&v);
        return Ok(());
    }
    if cmd == "storage" && action == "verify" {
        let v = api.call("POST", "/admin/storage/dr-scan", None, true)?;
        options.output(&v);
        return Ok(());
    }
    if cmd == "storage" && action == "migrate" {
        let target = std::env::var("STORAGE_PROVIDER").unwrap_or_default();
        if target.is_empty() {
            return Err("--target is required or set STORAGE_PROVIDER".into());
        }
        options.output(&api.call(
            "POST",
            &format!("/admin/storage/migrate?target={target}"),
            None,
            true,
        )?);
        return Ok(());
    }
    if cmd == "user" && action == "create" {
        let fs = flags::parse(
            "user create",
            args,
            &["email", "display", "password", "password-file"],
            &["password-stdin"],
            false,
        );
        let email = fs.get("email");
        if email.is_empty() {
            return Err("--email is required".into());
        }
        let secret = flags::secret(&fs, "password", "initial password")?;
        let v = api.call("POST", "/admin/users", Some(serde_json::json!({"email":email,"display_name":fs.get("display"),"password":secret})), true)?;
        if options.json {
            options.output(&v);
        } else {
            println!("User {email} created (id {}).", go_value(&v["id"]));
        }
        return Ok(());
    }
    if cmd == "user" && action == "list" {
        options.list(&api.call("GET", "/admin/users", None, true)?);
        return Ok(());
    }
    if cmd == "user" && action == "delete" {
        let email = args.first().ok_or("email required")?;
        options.confirm(&format!("Delete user {email}"))?;
        api.call(
            "DELETE",
            &format!("/admin/users?email={email}"),
            None,
            false,
        )?;
        return Ok(());
    }
    if cmd == "user" && action == "password" {
        let fs = flags::parse(
            "user password",
            args,
            &["new-password", "new-password-file"],
            &["new-password-stdin"],
            true,
        );
        let email = fs.positional.first().ok_or("usage: mailctl user password <email> (--new-password-file <path> | --new-password-stdin)")?;
        let secret = flags::secret(&fs, "new-password", "new password")?;
        if secret.is_empty() {
            return Err("a new password is required: pass --new-password-file (0600) or --new-password-stdin".into());
        }
        api.call(
            "PUT",
            &format!("/admin/users/{email}/password"),
            Some(serde_json::json!({"new_password":secret})),
            false,
        )?;
        if options.json {
            options.output(&serde_json::json!({"status":"ok","email":email}));
        } else {
            println!("Password updated for {email}.");
        }
        return Ok(());
    }
    if cmd == "user" && action == "quota" {
        if args.len() < 2 {
            return Err("usage: mailctl user quota get <email> | set <email> <bytes>".into());
        }
        let email = &args[1];
        if email.is_empty() {
            return Err("email is required".into());
        }
        let users = api.call("GET", "/admin/users", None, true)?;
        let user = users
            .as_array()
            .into_iter()
            .flatten()
            .find(|u| u["email"].as_str() == Some(email))
            .ok_or_else(|| format!("no user found with email {email:?}"))?;
        let path = format!("/admin/users/{}/quota", user["id"].as_i64().unwrap_or(0));
        if args[0] == "get" {
            options.output(&api.call("GET", &path, None, true)?);
            return Ok(());
        }
        if args[0] == "set" {
            let bytes = args
                .get(2)
                .ok_or("usage: mailctl user quota set <email> <bytes>")?;
            let n = bytes.parse::<i64>().map_err(|_| {
                format!(
                    "invalid bytes {bytes:?}: strconv.ParseInt: parsing {bytes:?}: {}",
                    if bytes.parse::<i128>().is_ok() {
                        "value out of range"
                    } else {
                        "invalid syntax"
                    }
                )
            })?;
            if n <= 0 {
                return Err("quota bytes must be positive; the server ignores non-positive values (a quota cannot be zeroed this way)".into());
            }
            api.call(
                "PUT",
                &path,
                Some(serde_json::json!({"quotaBytes":n})),
                false,
            )?;
            if options.json {
                options.output(&serde_json::json!({"email":email,"quotaBytes":n}));
            } else {
                println!("Quota set for {email}: {n} bytes.");
            }
            return Ok(());
        }
        Err(format!("unknown quota action: {} (try: get, set)", args[0]))?
    }
    if cmd == "user" && action == "bulk-create" {
        let path = args
            .first()
            .ok_or("usage: mailctl user bulk-create <file.csv>")?;
        let data = std::fs::read(path)
            .map_err(|e| format!("read {path}: open {path}: {}", flags::go_io_error(&e)))?;
        let mut reader = csv::ReaderBuilder::new().from_reader(data.as_slice());
        let headers = reader
            .headers()
            .map_err(|e| format!("parse CSV: read header: {e}"))?
            .clone();
        if headers.is_empty() {
            return Err("parse CSV: read header: EOF".into());
        }
        if headers.get(0) != Some("email") {
            return Err(format!(
                "parse CSV: first column must be 'email', got {:?}",
                headers.get(0).unwrap_or("")
            ));
        }
        let mut created = 0;
        let mut failed = 0;
        for row in reader.records() {
            let Ok(row) = row else {
                break;
            };
            let user: serde_json::Map<String, Value> = headers
                .iter()
                .zip(row.iter())
                .map(|(k, v)| (k.to_owned(), Value::String(v.to_owned())))
                .collect();
            let email = user
                .get("email")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            match api.call("POST", "/admin/users", Some(Value::Object(user)), true) {
                Ok(_) => {
                    created += 1;
                    if !options.quiet {
                        println!("  CREATED {email}");
                    }
                }
                Err(e) => {
                    failed += 1;
                    eprintln!("  FAIL {email}: {e}");
                }
            }
        }
        if !options.quiet {
            println!("Done: {created} created, {failed} failed");
        }
        if failed > 0 {
            return Err(format!("bulk-create: {failed}/{} failed", created + failed));
        }
        return Ok(());
    }
    if cmd == "webhook" && action == "list" {
        options.list(&api.call("GET", "/admin/webhooks", None, true)?);
        return Ok(());
    }
    if cmd == "webhook" && action == "events" {
        options.list(&api.call("GET", "/admin/webhooks/events", None, true)?);
        return Ok(());
    }
    if cmd == "webhook" && action == "deliveries" {
        options.list(&api.call(
            "GET",
            &format!(
                "/admin/webhooks/{}/deliveries",
                args.first().ok_or("webhook ID required")?
            ),
            None,
            true,
        )?);
        return Ok(());
    }
    if cmd == "webhook" && action == "create" {
        let fs = flags::parse("webhook create", args, &["url", "events"], &[], false);
        if fs.get("url").is_empty() || fs.get("events").is_empty() {
            return Err("--url and --events are required".into());
        }
        let v = api.call("POST", "/admin/webhooks", Some(serde_json::json!({"url":fs.get("url"),"eventTypes":fs.get("events").split(',').collect::<Vec<_>>()})), true)?;
        if options.json {
            options.output(&v);
        } else {
            println!("Webhook created (id {}).\n\n  Signing secret (save now — cannot be recovered):\n  {}", go_value(&v["id"]), v["secret"].as_str().unwrap_or(""));
        }
        return Ok(());
    }
    if cmd == "webhook" && action == "rotate-secret" {
        let id = args.first().ok_or("webhook ID required")?;
        let v = api.call(
            "POST",
            &format!("/admin/webhooks/{id}/rotate-secret"),
            None,
            true,
        )?;
        if options.json {
            options.output(&v);
        } else {
            println!("Webhook {id} secret rotated.\n\n  New signing secret (save now — cannot be recovered):\n  {}\n\nUpdate your receiver's HMAC verification with this secret. The previous\nsecret stays valid briefly (prev_secret) so in-flight deliveries don't break.", v["secret"].as_str().unwrap_or(""));
        }
        return Ok(());
    }
    if cmd == "webhook" && action == "delete" {
        let id = args.first().ok_or("webhook ID required")?;
        options.confirm(&format!("Delete webhook {id}"))?;
        api.call("DELETE", &format!("/admin/webhooks/{id}"), None, false)?;
        return Ok(());
    }
    if cmd == "system" && action == "status" {
        let v = api.call("GET", "/admin/system/status", None, true)?;
        if options.json {
            options.output(&v);
        } else {
            for (label, key) in [
                ("Status:       ", "status"),
                ("PID:          ", "pid"),
                ("Uptime:       ", "uptime_sec"),
                ("Version:      ", "version"),
                ("Goroutines:   ", "goroutines"),
                ("Memory:       ", "memory_mb"),
                ("Started:      ", "started_at"),
            ] {
                let suffix = match key {
                    "uptime_sec" => " seconds",
                    "memory_mb" => " MB",
                    _ => "",
                };
                println!("{label}{}{suffix}", go_value(&v[key]));
            }
        }
        return Ok(());
    }
    if cmd == "system" && action == "restart" {
        let mode = if args.first().map(String::as_str) == Some("--full") {
            "full_restart"
        } else {
            "hot_reload"
        };
        options.confirm(&format!("Restart system (mode: {mode})"))?;
        let v = api.call(
            "POST",
            "/admin/system/restart",
            Some(serde_json::json!({"mode":mode})),
            true,
        )?;
        if options.json {
            options.output(&v);
        } else {
            println!(
                "Restarting: {} (mode: {})",
                go_value(&v["status"]),
                go_value(&v["mode"])
            );
        }
        return Ok(());
    }
    if cmd == "system" && action == "stop" {
        options.confirm("Stop system")?;
        let v = api.call(
            "POST",
            "/admin/system/stop",
            Some(serde_json::json!({"drain_timeout_sec":30})),
            true,
        )?;
        if options.json {
            options.output(&v);
        } else {
            println!("Stopping: {}", go_value(&v["status"]));
        }
        return Ok(());
    }
    if cmd == "auto-update" && action == "status" {
        let v = api.call("GET", "/admin/system/auto-update", None, true)?;
        if options.json {
            options.output(&v);
        } else {
            for (label, key) in [
                ("Enabled:       ", "enabled"),
                ("Channel:       ", "channel"),
                ("Interval:      ", "check_interval"),
                ("Auto-apply:    ", "auto_apply_safe"),
            ] {
                println!("{label}{}", go_value(&v[key]));
            }
        }
        return Ok(());
    }
    if cmd == "auto-update" && action == "enable" {
        api.call("PUT", "/admin/system/auto-update", Some(serde_json::json!({"enabled":true,"channel":"stable","check_interval":"daily","auto_apply_safe":false,"notify_admin":true,"require_confirm_breaking":true})), false)?;
        if options.json {
            options.output(&serde_json::json!({"enabled":true}));
        } else {
            println!("Auto-update enabled");
        }
        return Ok(());
    }
    if cmd == "auto-update" && action == "disable" {
        api.call(
            "PUT",
            "/admin/system/auto-update",
            Some(serde_json::json!({"enabled":false})),
            false,
        )?;
        if options.json {
            options.output(&serde_json::json!({"enabled":false}));
        } else {
            println!("Auto-update disabled");
        }
        return Ok(());
    }
    if cmd == "tls" && action == "set" {
        let fs = flags::parse(
            "tls set",
            args,
            &["challenge", "domains", "email", "dns-provider"],
            &[],
            false,
        );
        let mut body = serde_json::Map::new();
        for (flag, key) in [
            ("challenge", "tls.autocert_challenge"),
            ("domains", "tls.autocert_domains"),
            ("email", "tls.autocert_email"),
            ("dns-provider", "tls.dns_provider"),
        ] {
            if !fs.get(flag).is_empty() {
                body.insert(key.to_owned(), Value::String(fs.get(flag).to_owned()));
            }
        }
        api.call("PUT", "/admin/tls/config", Some(Value::Object(body)), false)?;
        println!("TLS config saved. Restart gateway to apply.");
        return Ok(());
    }
    if cmd == "tls" && action == "status" {
        let raw = api.call("GET", "/admin/tls/status", None, true)?;
        let v: models::Tls = if raw.is_null() {
            Default::default()
        } else {
            serde_json::from_value(raw).map_err(|e| e.to_string())?
        };
        if options.json {
            options.typed(&v);
        } else {
            println!(
                "TLS: {}\nChallenge: {}\nDomains: [{}]\nEmail: {}\nDNS Provider: {}\nCache Dir: {}",
                enabled(v.enabled),
                v.challenge,
                v.domains.unwrap_or_default().join(" "),
                v.email,
                v.dns_provider,
                v.cache_dir
            );
            if let Some(c) = v.cert_info {
                println!("\nCertificate:\n  Subject:   {}\n  Issuer:    {}\n  Not Before: {}\n  Not After:  {}\n  Days Left:  {}", c.subject,c.issuer,c.not_before,c.not_after,c.days_left);
            }
        }
        return Ok(());
    }
    if cmd == "spam" && action == "status" {
        let raw = api.call("GET", "/admin/spam", None, true)?;
        let v: models::Spam = if raw.is_null() {
            Default::default()
        } else {
            serde_json::from_value(raw).map_err(|e| e.to_string())?
        };
        if options.json {
            options.typed(&v);
        } else {
            println!("Status:     {}\nModels:     {} users trained ({} opted out)\nSamples:    {} total ({:.0} avg/user)\nActive:     {} users this week", enabled(v.enabled),v.total_models,v.disabled_users,v.total_samples,v.avg_samples,v.active_week);
            if v.total_classified > 0 {
                println!(
                    "Accuracy:   {:.2}% FP rate ({} rescues / {} classified)",
                    v.fp_rate * 100.0,
                    v.total_fp,
                    v.total_classified
                );
            }
        }
        return Ok(());
    }
    if cmd == "spam" && action == "reset" {
        let id = args.first().ok_or("usage: mailctl spam reset <userId>")?;
        options.confirm(&format!("Reset spam model for user {id}"))?;
        api.call("DELETE", &format!("/admin/spam/models/{id}"), None, false)?;
        if options.json {
            options.output(&serde_json::json!({"status":"reset","user":id}));
        } else {
            println!("Spam model reset for user {id}");
        }
        return Ok(());
    }
    if cmd == "ad" && action == "sync" {
        let raw = api.call("POST", "/admin/ad/sync", None, true)?;
        let v: models::Sync = if raw.is_null() {
            Default::default()
        } else {
            serde_json::from_value(raw).map_err(|e| e.to_string())?
        };
        if options.json {
            options.typed(&v);
        } else {
            println!("Sync complete: checked={} created={} updated={} disabled={} skipped={} errors={} duration={}",v.checked,v.created,v.updated,v.disabled,v.skipped,v.errors,v.duration);
        }
        if v.errors > 0 {
            return Err(format!("sync completed with {} error(s)", v.errors));
        }
        return Ok(());
    }
    if cmd == "ad" && action == "sync-log" {
        let entries: Option<Vec<models::SyncLog>> =
            serde_json::from_value(api.call("GET", "/admin/ad/sync-log", None, true)?)
                .map_err(|e| e.to_string())?;
        if options.json {
            options.typed(&entries);
        } else {
            let entries = entries.unwrap_or_default();
            if entries.is_empty() {
                println!("No sync log entries.");
            } else {
                println!(
                    "{:<20} {:<7} {:<7} {:<7} {:<8} {:<7} {:<6} Duration(s)",
                    "SyncedAt", "Checked", "Created", "Updated", "Disabled", "Skipped", "Errors"
                );
                for e in entries {
                    println!(
                        "{:<20} {:<7} {:<7} {:<7} {:<8} {:<7} {:<6} {}",
                        e.synced_at,
                        e.checked,
                        e.created,
                        e.updated,
                        e.disabled,
                        e.skipped,
                        e.errors,
                        e.duration_seconds
                    );
                }
            }
        }
        return Ok(());
    }
    if cmd == "ad" && action == "health" {
        let raw = api.call("GET", "/admin/ad/health", None, true)?;
        let v: models::DirectoryHealth = if raw.is_null() {
            Default::default()
        } else {
            serde_json::from_value(raw).map_err(|e| e.to_string())?
        };
        if options.json {
            options.typed(&v);
        } else {
            println!("Status: {}\nLast sync: {}\nChecked: {}  Created: {}  Updated: {}  Disabled: {}  Skipped: {}  Errors: {}\nPending conflicts: {}",v.status,v.last_sync.as_deref().unwrap_or("never"),v.checked,v.created,v.updated,v.disabled,v.skipped,v.errors,v.pending_conflicts);
        }
        if v.status != "healthy" {
            return Err(format!("directory sync status: {}", v.status));
        }
        return Ok(());
    }
    if cmd == "ldap" && action == "sync" {
        let raw = api.call("POST", "/admin/ldap/sync", None, true)?;
        let v: models::Sync = if raw.is_null() {
            Default::default()
        } else {
            serde_json::from_value(raw).map_err(|e| e.to_string())?
        };
        if options.json {
            options.typed(&v);
        } else {
            println!("Sync complete: checked={} created={} updated={} disabled={} skipped={} errors={} duration={}",v.checked,v.created,v.updated,v.disabled,v.skipped,v.errors,v.duration);
        }
        if v.errors > 0 {
            return Err(format!("sync completed with {} error(s)", v.errors));
        }
        return Ok(());
    }
    if cmd == "ldap" && action == "sync-log" {
        let entries: Option<Vec<models::SyncLog>> =
            serde_json::from_value(api.call("GET", "/admin/ldap/sync-log", None, true)?)
                .map_err(|e| e.to_string())?;
        if options.json {
            options.typed(&entries);
        } else {
            let entries = entries.unwrap_or_default();
            if entries.is_empty() {
                println!("No sync log entries.");
            } else {
                println!(
                    "{:<20} {:<7} {:<7} {:<7} {:<8} {:<7} {:<6} Duration(s)",
                    "SyncedAt", "Checked", "Created", "Updated", "Disabled", "Skipped", "Errors"
                );
                for e in entries {
                    println!(
                        "{:<20} {:<7} {:<7} {:<7} {:<8} {:<7} {:<6} {}",
                        e.synced_at,
                        e.checked,
                        e.created,
                        e.updated,
                        e.disabled,
                        e.skipped,
                        e.errors,
                        e.duration_seconds
                    );
                }
            }
        }
        return Ok(());
    }
    if cmd == "ldap" && action == "health" {
        let raw = api.call("GET", "/admin/ldap/health", None, true)?;
        let v: models::DirectoryHealth = if raw.is_null() {
            Default::default()
        } else {
            serde_json::from_value(raw).map_err(|e| e.to_string())?
        };
        if options.json {
            options.typed(&v);
        } else {
            println!("Status: {}\nLast sync: {}\nChecked: {}  Created: {}  Updated: {}  Disabled: {}  Skipped: {}  Errors: {}\nPending conflicts: {}",v.status,v.last_sync.as_deref().unwrap_or("never"),v.checked,v.created,v.updated,v.disabled,v.skipped,v.errors,v.pending_conflicts);
        }
        if v.status != "healthy" {
            return Err(format!("directory sync status: {}", v.status));
        }
        return Ok(());
    }
    let actions = match cmd {
        "user" => "list, create, delete, password, quota, bulk-create",
        "domain" => "add, list, delete",
        "webhook" => "list, create, delete, rotate-secret, deliveries, events",
        "config" => "get, list",
        "migration" => "list, status, cancel",
        "auto-update" => "status, enable, disable",
        "system" => "status, restart, stop",
        "spam" => "status, reset",
        "storage" => "status, migrate, verify",
        "ad" | "ldap" => "sync, sync-log, health",
        "tls" => return Err(format!("tls: unknown action {action:?} (use: status, set)")),
        _ => return Err(format!("{cmd} is not ported yet")),
    };
    Err(format!("unknown {cmd} action: {action} (try: {actions})"))
}

#[derive(Default)]
struct Options {
    json: bool,
    quiet: bool,
    yes: bool,
}
impl Options {
    fn parse(args: &[String]) -> (Self, &[String]) {
        let mut options = Self::default();
        let mut short_yes = false;
        let mut i = 0;
        while let Some(arg) = args.get(i) {
            if arg == "--" {
                return (options, &args[i + 1..]);
            }
            if !arg.starts_with('-') || arg == "-" {
                break;
            }
            let (name, value) = arg
                .trim_start_matches('-')
                .split_once('=')
                .unwrap_or((arg.trim_start_matches('-'), "true"));
            let flag = match name {
                "json" => &mut options.json,
                "quiet" => &mut options.quiet,
                "yes" => &mut options.yes,
                "y" => &mut short_yes,
                _ => {
                    options.yes |= short_yes;
                    return (options, args);
                }
            };
            *flag = match value {
                "true" | "1" | "t" | "TRUE" | "T" | "True" => true,
                "false" | "0" | "f" | "FALSE" | "F" | "False" => false,
                _ => {
                    options.yes |= short_yes;
                    return (options, args);
                }
            };
            i += 1;
        }
        options.yes |= short_yes;
        (options, &args[i..])
    }
    fn list(&self, value: &Value) {
        if self.json || self.quiet {
            self.output(value);
            return;
        }
        let items = value.as_array().cloned().unwrap_or_default();
        let Some(first) = items.first() else {
            println!("(empty)");
            return;
        };
        let headers = first
            .as_object()
            .map(|m| m.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut rows = vec![headers.clone()];
        rows.extend(items.iter().map(|item| {
            headers
                .iter()
                .map(|h| go_value(&item[h]))
                .collect::<Vec<_>>()
        }));
        let widths: Vec<usize> = (0..headers.len())
            .map(|i| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0) + 2)
            .collect();
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                print!("{cell}");
                if i + 1 < row.len() {
                    print!(
                        "{}",
                        " ".repeat(widths[i].saturating_sub(cell.chars().count()))
                    );
                }
            }
            println!();
        }
    }
    fn typed<T: serde::Serialize>(&self, value: &T) {
        if self.quiet {
            return;
        }
        let s = serde_json::to_string_pretty(value).unwrap();
        println!(
            "{}",
            s.replace('<', "\\u003c")
                .replace('>', "\\u003e")
                .replace('&', "\\u0026")
                .replace('\u{2028}', "\\u2028")
                .replace('\u{2029}', "\\u2029")
        );
    }
    fn output(&self, value: &Value) {
        if self.quiet {
            return;
        }
        if self.json {
            println!("{}", go_json_generic(value, true));
        } else {
            println!("{}", go_value(value));
        }
    }
    fn confirm(&self, action: &str) -> Result<(), String> {
        if self.yes {
            return Ok(());
        }
        use std::io::Write;
        eprint!("{action} — are you sure? (type 'yes' to confirm): ");
        std::io::stderr().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).ok();
        if answer
            .split_whitespace()
            .next()
            .unwrap_or("")
            .eq_ignore_ascii_case("yes")
        {
            Ok(())
        } else {
            Err("cancelled".into())
        }
    }
}

fn enabled(value: bool) -> &'static str {
    if value {
        "enabled"
    } else {
        "disabled"
    }
}
