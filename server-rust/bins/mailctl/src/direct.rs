//! Local operator CLI: credential authority and frozen-Go process behaviour.
use setjoin_pg::operator::OperatorConnection;
use std::collections::BTreeMap;
mod bootstrap;
mod push;
mod scim;
mod smime;
mod sources;

use setjoin_schema::MIGRATIONS;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

async fn database(owner: bool) -> Result<OperatorConnection, String> {
    let keys: &[&str] = if owner {
        &[
            "DB_DIRECT_OWNER_DSN",
            "DB_OWNER_DSN",
            "DB_DIRECT_DSN",
            "DB_DSN",
        ]
    } else {
        &["DB_DSN"]
    };
    let dsn = keys.iter().map(|k| env(k)).find(|s| !s.is_empty()).ok_or_else(|| {
        if owner { "DB_DIRECT_OWNER_DSN, DB_OWNER_DSN, DB_DIRECT_DSN or DB_DSN environment variable is required" }
        else { "DB_DSN environment variable is required" }.to_owned()
    })?;
    OperatorConnection::connect(&dsn).await
}

pub fn run(cmd: &str, action: &str, args: &[String]) -> i32 {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    match runtime.block_on(execute(cmd, action, args)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

async fn execute(cmd: &str, action: &str, args: &[String]) -> Result<i32, String> {
    match (cmd, action) {
        ("push", _) => {
            push::execute(action, args).await?;
            Ok(0)
        }
        ("smime", _) => {
            smime::execute(action, args).await?;
            Ok(0)
        }
        ("sources", _) => {
            sources::execute(action, args).await?;
            Ok(0)
        }
        ("bootstrap-admin", _) => {
            bootstrap::execute(action, args).await?;
            Ok(0)
        }
        ("scim", _) => {
            scim::execute(action, args).await?;
            Ok(0)
        }
        ("schema", "apply") => {
            let fs = crate::flags::parse("schema apply", args, &[], &["yes", "y"], false);
            let mut db = database(true).await?;
            let current: i32 = match db
                .query(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                    &[],
                )
                .await
            {
                Ok(rows) => rows[0].get(0),
                Err(e) if e.ends_with("(SQLSTATE 42P01)") => 0,
                Err(e) => return Err(format!("reading schema version: {e}")),
            };
            let expected = MIGRATIONS.last().unwrap().0;
            if current == 0 {
                return Err("database has no baseline (schema version 0) — load it first:\n  prod: deploy/scripts/install.sh\n  dev:  bash scripts/load-test-schema.sh\nthen re-run 'mailctl schema apply' for the forward migrations".into());
            }
            let pending: Vec<_> = MIGRATIONS.iter().filter(|m| m.0 > current).collect();
            if pending.is_empty() {
                println!("database schema is up to date (version {current})");
                return Ok(0);
            }
            println!(
                "pending (current={current} → target={expected}): {}",
                pending.iter().map(|m| m.1).collect::<Vec<_>>().join(", ")
            );
            let opts = crate::Options {
                json: false,
                quiet: false,
                yes: fs.boolean("yes") || fs.boolean("y"),
            };
            opts.confirm(&format!(
                "apply {} database schema migration(s)",
                pending.len()
            ))
            .map_err(|_| "aborted")?;
            for (.., name, sql) in pending {
                db.apply_migration(name, sql).await?;
                println!("  applied {name}");
            }
            println!("database schema is now at version {expected}");
            Ok(0)
        }
        ("schema", "check") => {
            let fs = crate::flags::parse("schema check", args, &[], &["json"], false);
            let db = database(true).await?;
            let current: i32 = match db
                .query(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                    &[],
                )
                .await
            {
                Ok(rows) => rows[0].get(0),
                Err(e) if e.ends_with("(SQLSTATE 42P01)") => 0,
                Err(e) => return Err(format!("reading schema version: {e}")),
            };
            let expected = MIGRATIONS.last().unwrap().0;
            let pending: Vec<_> = MIGRATIONS
                .iter()
                .filter(|m| m.0 > current)
                .map(|m| m.1)
                .collect();
            if fs.boolean("json") {
                println!(
                    "{}",
                    serde_json::json!({"current":current,"expected":expected,"pending":pending,"up_to_date":current>=expected})
                );
            } else {
                println!("database schema version: current={current} expected={expected}");
                if current >= expected {
                    println!("up to date");
                } else {
                    println!(
                        "BEHIND by {} migration(s): {}\napply with: mailctl schema apply",
                        pending.len(),
                        pending.join(", ")
                    );
                }
            }
            Ok(if current >= expected { 0 } else { 1 })
        }
        ("schema", _) => Err(format!(
            "unknown schema action: {action}. Try: check, apply"
        )),
        _ => unreachable!(),
    }
}

fn parse_silent(
    args: &[String],
    strings: &[&str],
    bools: &[&str],
) -> Result<(BTreeMap<String, String>, Vec<String>), String> {
    let mut values = BTreeMap::new();
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        if arg == "--" {
            return Ok((values, args[i + 1..].to_vec()));
        }
        if arg == "-" || !arg.starts_with('-') {
            return Ok((values, args[i..].to_vec()));
        }
        let raw = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .unwrap();
        let (name, inline) = raw
            .split_once('=')
            .map(|(k, v)| (k, Some(v)))
            .unwrap_or((raw, None));
        if matches!(name, "h" | "help") {
            return Err("flag: help requested".into());
        }
        if !strings.contains(&name) && !bools.contains(&name) {
            return Err(format!("flag provided but not defined: -{name}"));
        }
        let value = if bools.contains(&name) {
            let value = inline.unwrap_or("true");
            if !matches!(
                value,
                "true"
                    | "false"
                    | "1"
                    | "0"
                    | "t"
                    | "f"
                    | "T"
                    | "F"
                    | "TRUE"
                    | "FALSE"
                    | "True"
                    | "False"
            ) {
                return Err(format!(
                    "invalid boolean value {value:?} for -{name}: parse error"
                ));
            }
            value
        } else if let Some(v) = inline {
            v
        } else {
            i += 1;
            args.get(i)
                .map(String::as_str)
                .ok_or_else(|| format!("flag needs an argument: -{name}"))?
        };
        values.insert(name.to_owned(), value.to_owned());
        i += 1;
    }
    Ok((values, Vec::new()))
}
fn value<'a>(fs: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    fs.get(key).map(String::as_str).unwrap_or("")
}
fn truth(value: &str) -> bool {
    matches!(value, "true" | "1" | "t" | "T" | "TRUE" | "True")
}
fn random_hex() -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "random generation failed")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
