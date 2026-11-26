//! `mailctl work` / `mailctl workq` — durable WorkQueue stats and DLQ
//! inspection, replay, and purge commands (Wave 2.1, #548).

use setjoin_pg::operator::OperatorConnection;
use setjoin_workqueue::operator as wq;

async fn work_database() -> Result<OperatorConnection, String> {
    // Worker reducers require rolbypassrls OR rolsuper (BZ003); prioritize
    // DB_WORKER_DSN ahead of DB_OWNER_DSN (setjoin_owner is NOBYPASSRLS).
    let keys = [
        "DB_WORKER_DSN",
        "DB_DIRECT_DSN",
        "DB_DSN",
        "DB_DIRECT_OWNER_DSN",
        "DB_OWNER_DSN",
    ];
    let dsn = keys
        .iter()
        .map(|k| super::env(k))
        .find(|s| !s.is_empty())
        .ok_or_else(|| {
            "DB_WORKER_DSN, DB_DIRECT_DSN, DB_DSN, DB_DIRECT_OWNER_DSN or DB_OWNER_DSN environment variable is required"
                .to_owned()
        })?;
    OperatorConnection::connect(&dsn).await
}

pub(super) async fn execute(action: &str, args: &[String]) -> Result<(), String> {
    match action {
        "stats" => execute_stats(args).await,
        "dlq" => execute_dlq(args).await,
        other => Err(format!("unknown work action: {other} (try: stats, dlq)")),
    }
}

/// Parse flags in any position (before or after positional arguments) so both
/// `mailctl work dlq inspect 42 --json` and `mailctl work dlq inspect --json 42`
/// work identically. Respects `--` to end flag parsing.
fn parse_work_args(
    args: &[String],
    string_flags: &[&str],
    bool_flags: &[&str],
) -> Result<(std::collections::BTreeMap<String, String>, Vec<String>), String> {
    let mut flags_first = Vec::with_capacity(args.len());
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            positional.extend_from_slice(&args[i + 1..]);
            break;
        }
        if a.starts_with('-') && a.len() > 1 {
            let trimmed = a.trim_start_matches('-');
            let (name, eq_val) = match trimmed.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (trimmed, None),
            };
            if string_flags.contains(&name) {
                match eq_val {
                    Some("") => {
                        return Err(format!("flag --{name} must not be empty"));
                    }
                    Some(_) => {
                        flags_first.push(a.clone());
                    }
                    None => {
                        if i + 1 >= args.len() {
                            return Err(format!("flag --{name} requires a value"));
                        }
                        if args[i + 1].is_empty() {
                            return Err(format!("flag --{name} must not be empty"));
                        }
                        flags_first.push(a.clone());
                        i += 1;
                        flags_first.push(args[i].clone());
                    }
                }
            } else {
                flags_first.push(a.clone());
            }
        } else {
            positional.push(a.clone());
        }
        i += 1;
    }
    let (fs, extra) = super::parse_silent(&flags_first, string_flags, bool_flags)?;
    positional.extend(extra);
    Ok((fs, positional))
}

async fn execute_stats(args: &[String]) -> Result<(), String> {
    let (fs, rest) = parse_work_args(args, &[], &["json", "quiet"])?;
    if !rest.is_empty() {
        return Err(format!("unexpected argument: {}", rest[0]));
    }
    let db = work_database().await?;
    let stats = wq::stats(&db).await?;
    if super::truth(super::value(&fs, "json")) {
        println!(
            "{}",
            serde_json::to_string_pretty(&stats).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "pending:             {}\nleased:              {}\ndead_letters:        {}\noldest_due_age_secs: {:.3}",
            stats.pending, stats.leased, stats.dead_letters, stats.oldest_due_age_secs
        );
    }
    Ok(())
}

async fn execute_dlq(args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: mailctl work dlq list|inspect|replay|purge [flags...]".into());
    };
    let rest = &args[1..];
    match sub {
        "list" => dlq_list(rest).await,
        "inspect" => dlq_inspect(rest).await,
        "replay" => dlq_replay(rest).await,
        "purge" => dlq_purge(rest).await,
        other => Err(format!(
            "unknown work dlq action: {other} (try: list, inspect, replay, purge)"
        )),
    }
}

async fn dlq_list(args: &[String]) -> Result<(), String> {
    let (fs, pos) = parse_work_args(
        args,
        &["kind", "limit", "offset"],
        &["include-replayed", "json", "quiet"],
    )?;
    if !pos.is_empty() {
        return Err(format!("unexpected argument: {}", pos[0]));
    }
    let kind = super::value(&fs, "kind");
    let kind_opt = (!kind.is_empty()).then_some(kind);
    let include_replayed = super::truth(super::value(&fs, "include-replayed"));
    let limit = parse_i32_opt(super::value(&fs, "limit"), 50, "limit")?.clamp(1, 500);
    let offset = parse_i32_opt(super::value(&fs, "offset"), 0, "offset")?.max(0);

    let db = work_database().await?;
    let rows = wq::dlq_list(&db, kind_opt, include_replayed, limit, offset).await?;
    if super::truth(super::value(&fs, "json")) {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
        );
    } else if rows.is_empty() {
        println!("No dead-letter items.");
    } else {
        println!(
            "{:<8} {:<30} {:<8} {:<26} Error",
            "ID", "Kind", "Attempts", "DeadLetteredAt"
        );
        for row in rows {
            let err_preview: String = row.last_error.chars().take(80).collect();
            println!(
                "{:<8} {:<30} {:<8} {:<26} {}",
                row.id,
                row.kind,
                format!("{}/{}", row.attempts, row.max_attempts),
                row.dead_lettered_at,
                err_preview.replace('\n', " ")
            );
        }
    }
    Ok(())
}

async fn dlq_inspect(args: &[String]) -> Result<(), String> {
    let (fs, pos) = parse_work_args(args, &[], &["json", "quiet"])?;
    let id_str = pos
        .first()
        .ok_or("usage: mailctl work dlq inspect <id> [--json]")?;
    let id: i64 = id_str
        .parse()
        .map_err(|_| format!("invalid dead-letter id: {id_str:?}"))?;
    let db = work_database().await?;
    let Some(row) = wq::dlq_inspect(&db, id).await? else {
        return Err(format!("dead-letter item {id} not found"));
    };
    if super::truth(super::value(&fs, "json")) {
        println!(
            "{}",
            serde_json::to_string_pretty(&row).map_err(|e| e.to_string())?
        );
    } else {
        println!("ID:                   {}", row.id);
        println!("Work Item ID:         {}", row.work_item_id);
        println!("Kind:                 {}", row.kind);
        println!(
            "Idempotency Key:      {}",
            row.idempotency_key.as_deref().unwrap_or("<none>")
        );
        println!("Priority:             {}", row.priority);
        println!(
            "Attempts:             {}/{}",
            row.attempts, row.max_attempts
        );
        println!(
            "Failed By:            {}",
            row.failed_by.as_deref().unwrap_or("<unknown>")
        );
        println!("Enqueued At:          {}", row.enqueued_at);
        println!("Dead-Lettered At:     {}", row.dead_lettered_at);
        println!(
            "Replayed At:          {}",
            row.replayed_at.as_deref().unwrap_or("<not replayed>")
        );
        if let Some(new_id) = row.replayed_work_item_id {
            println!("Replayed Work Item:   {new_id}");
        }
        println!("Last Error:\n{}", row.last_error);
        println!(
            "Payload:\n{}",
            serde_json::to_string_pretty(&row.payload).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}

async fn dlq_replay(args: &[String]) -> Result<(), String> {
    let (fs, pos) = parse_work_args(
        args,
        &["kind", "limit"],
        &[
            "all",
            "reset-idempotency",
            "force",
            "yes",
            "y",
            "json",
            "quiet",
        ],
    )?;
    let reset_idem = super::truth(super::value(&fs, "reset-idempotency"));
    let force = super::truth(super::value(&fs, "force"));
    let yes = super::truth(super::value(&fs, "yes")) || super::truth(super::value(&fs, "y"));
    let json_out = super::truth(super::value(&fs, "json"));
    let all_mode = super::truth(super::value(&fs, "all"));
    let kind = super::value(&fs, "kind");
    let kind_opt = (!kind.is_empty()).then_some(kind);

    if let Some(id_str) = pos.first() {
        if all_mode || kind_opt.is_some() {
            return Err("cannot combine positional <id> with --all or --kind".into());
        }
        let id: i64 = id_str
            .parse()
            .map_err(|_| format!("invalid dead-letter id: {id_str:?}"))?;
        let db = work_database().await?;
        let (dlq_id, work_item_id) = wq::dlq_replay_one(&db, id, reset_idem, force).await?;
        if json_out {
            println!(
                "{}",
                serde_json::json!({
                    "replayed": [{ "dlq_id": dlq_id, "work_item_id": work_item_id }],
                    "count": 1
                })
            );
        } else {
            println!("Replayed DLQ #{dlq_id} -> work item #{work_item_id}");
        }
        return Ok(());
    }

    if !all_mode && kind_opt.is_none() {
        return Err(
            "usage: mailctl work dlq replay <id> | --all [--kind <k>] [--limit <n>] [--reset-idempotency] [--force] [--yes]"
                .into(),
        );
    }
    let limit = parse_i32_opt(super::value(&fs, "limit"), 50, "limit")?.clamp(1, 500);
    let opts = crate::Options {
        json: json_out,
        quiet: super::truth(super::value(&fs, "quiet")),
        yes,
    };
    opts.confirm(&format!(
        "Replay up to {limit} dead-letter item(s){}",
        kind_opt
            .map(|k| format!(" of kind {k}"))
            .unwrap_or_default()
    ))?;

    let db = work_database().await?;
    let pairs = wq::dlq_replay_batch(&db, kind_opt, limit, reset_idem, force).await?;
    if json_out {
        let items: Vec<_> = pairs
            .iter()
            .map(|(dlq_id, work_item_id)| {
                serde_json::json!({"dlq_id": dlq_id, "work_item_id": work_item_id})
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({"replayed": items, "count": items.len()})
        );
    } else {
        println!("Replayed {} dead-letter item(s).", pairs.len());
        for (dlq_id, work_item_id) in pairs {
            println!("  DLQ #{dlq_id} -> work item #{work_item_id}");
        }
    }
    Ok(())
}

async fn dlq_purge(args: &[String]) -> Result<(), String> {
    let (fs, pos) = parse_work_args(
        args,
        &["kind", "older-than-days"],
        &["include-unreplayed", "yes", "y", "json", "quiet"],
    )?;
    let yes = super::truth(super::value(&fs, "yes")) || super::truth(super::value(&fs, "y"));
    let json_out = super::truth(super::value(&fs, "json"));
    let include_unreplayed = super::truth(super::value(&fs, "include-unreplayed"));
    let kind = super::value(&fs, "kind");
    let kind_opt = (!kind.is_empty()).then_some(kind);
    let older_raw = super::value(&fs, "older-than-days");
    let older_than_days = if older_raw.is_empty() {
        None
    } else {
        let d: i32 = older_raw
            .parse()
            .map_err(|_| format!("invalid --older-than-days: {older_raw:?}"))?;
        if d < 0 {
            return Err("--older-than-days must be >= 0".into());
        }
        Some(d)
    };
    let id = match pos.first() {
        Some(s) => Some(
            s.parse::<i64>()
                .map_err(|_| format!("invalid dead-letter id: {s:?}"))?,
        ),
        None => None,
    };
    if id.is_some() && (kind_opt.is_some() || older_than_days.is_some()) {
        return Err("cannot combine positional <id> with --kind or --older-than-days".into());
    }

    let opts = crate::Options {
        json: json_out,
        quiet: super::truth(super::value(&fs, "quiet")),
        yes,
    };
    let desc = match id {
        Some(id) => format!("Purge dead-letter item #{id}"),
        None => format!(
            "Purge dead-letter items{}{}",
            kind_opt
                .map(|k| format!(" of kind {k}"))
                .unwrap_or_default(),
            older_than_days
                .map(|d| format!(" older than {d} day(s)"))
                .unwrap_or_default()
        ),
    };
    opts.confirm(&desc)?;

    let db = work_database().await?;
    let deleted = wq::dlq_purge(&db, id, kind_opt, older_than_days, !include_unreplayed).await?;
    if json_out {
        println!("{}", serde_json::json!({"purged": deleted}));
    } else {
        println!("Purged {deleted} dead-letter item(s).");
    }
    Ok(())
}

fn parse_i32_opt(raw: &str, default: i32, name: &str) -> Result<i32, String> {
    if raw.is_empty() {
        return Ok(default);
    }
    raw.parse::<i32>()
        .map_err(|_| format!("invalid --{name}: {raw:?}"))
}
