//! Go flag.FlagSet compatibility for the small flagsets in this CLI slice.
use std::collections::BTreeMap;

pub struct Flags {
    values: BTreeMap<String, String>,
    pub positional: Vec<String>,
    order: Vec<String>,
}
impl Flags {
    pub fn boolean_alias(&self, names: &[&str]) -> Option<bool> {
        self.order
            .iter()
            .rev()
            .find(|k| names.contains(&k.as_str()))
            .map(|k| self.boolean(k))
    }

    pub fn get(&self, key: &str) -> &str {
        self.values.get(key).map(String::as_str).unwrap_or("")
    }
    pub fn set(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }
    pub fn boolean(&self, key: &str) -> bool {
        matches!(self.get(key), "true" | "1" | "t" | "T" | "TRUE" | "True")
    }
}

pub fn parse(
    command: &str,
    args: &[String],
    strings: &[&str],
    booleans: &[&str],
    interspersed: bool,
) -> Flags {
    let definition = definitions().get(command);
    let mut order = Vec::new();
    let mut values = BTreeMap::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        if arg == "--" {
            positional.extend_from_slice(&args[i + 1..]);
            break;
        }
        if arg == "-" || !arg.starts_with('-') {
            if interspersed {
                positional.push(arg.clone());
                i += 1;
                continue;
            }
            positional.extend_from_slice(&args[i..]);
            break;
        }
        let raw = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .unwrap();
        if definition.is_some() && (raw.starts_with(['-', '=']) || raw.is_empty()) {
            usage(command, &format!("bad flag syntax: {arg}\n"), 2);
        }
        let (name, inline) = raw
            .split_once('=')
            .map(|(k, v)| (k, Some(v)))
            .unwrap_or((raw, None));
        if matches!(name, "h" | "help") {
            usage(command, "", 0);
        }
        let kind = definition
            .and_then(|d| d.flags.get(name))
            .map(String::as_str);
        let allowed = definition
            .map(|d| d.flags.contains_key(name))
            .unwrap_or_else(|| strings.contains(&name) || booleans.contains(&name));
        if !allowed {
            usage(
                command,
                &format!("flag provided but not defined: -{name}\n"),
                2,
            );
        }
        let value;
        if kind == Some("Bool") || (definition.is_none() && booleans.contains(&name)) {
            value = inline.unwrap_or("true");
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
                usage(
                    command,
                    &format!("invalid boolean value {value:?} for -{name}: parse error\n"),
                    2,
                );
            }
        } else if let Some(v) = inline {
            value = v;
        } else {
            i += 1;
            value = args.get(i).map(String::as_str).unwrap_or_else(|| {
                usage(command, &format!("flag needs an argument: -{name}\n"), 2)
            });
        }
        let value = match kind {
            Some("Int" | "Int64") => parse_integer(value)
                .unwrap_or_else(|reason| {
                    usage(
                        command,
                        &format!("invalid value {value:?} for flag -{name}: {reason}\n"),
                        2,
                    )
                })
                .to_string(),
            Some("Duration") => {
                let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
                let valid = crate::part_b::duration(unsigned).is_some_and(|d| {
                    d.as_nanos() <= i64::MAX as u128 + u128::from(value.starts_with('-'))
                });
                if !valid {
                    usage(
                        command,
                        &format!("invalid value {value:?} for flag -{name}: parse error\n"),
                        2,
                    );
                }
                value.to_owned()
            }
            _ => value.to_owned(),
        };
        order.push(name.to_owned());
        values.insert(name.to_owned(), value);
        i += 1;
    }
    Flags {
        values,
        positional,
        order,
    }
}
fn usage(command: &str, error: &str, status: i32) -> ! {
    if let Some(d) = definitions().get(command) {
        if d.mode != "silent" {
            eprint!("{error}{}", d.help);
        }
        if d.mode == "exit" {
            std::process::exit(status);
        }
        let message = d.override_error.as_deref().unwrap_or(if status == 0 {
            "flag: help requested"
        } else {
            error.trim_end_matches('\n')
        });
        eprintln!("Error: {message}");
        std::process::exit(d.status.unwrap_or(1));
    }
    let helps: BTreeMap<String, String> =
        serde_json::from_str(include_str!("flags_help.json")).unwrap();
    eprint!("{error}{}", helps[command]);
    std::process::exit(status);
}

pub fn secret(flags: &Flags, name: &str, label: &str) -> Result<String, String> {
    use std::io::{BufRead, Read};
    if flags.set(name) {
        return Err(format!("--{name} must not be passed on the command line (process listings and shell history expose it); pass --{name}-file (0600) or --{name}-stdin instead"));
    }
    let file_key = format!("{name}-file");
    let stdin_key = format!("{name}-stdin");
    let path = flags.get(&file_key);
    if !path.is_empty() && flags.boolean(&stdin_key) {
        return Err(format!("choose only one of --{file_key} or --{stdin_key}"));
    }
    if !path.is_empty() {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| format!("read {label}: lstat {path}: {}", go_io_error(&e)))?;
        #[cfg(unix)]
        let public = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o077 != 0
        };
        #[cfg(not(unix))]
        let public = false;
        if !metadata.is_file() || public || metadata.len() < 1 || metadata.len() > 4096 {
            return Err(format!(
                "{label} must be a regular non-symlink 0600 file of 1-4096 bytes"
            ));
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("read {label}: open {path}: {}", go_io_error(&e)))?;
        let raw = raw.strip_suffix('\n').unwrap_or(&raw);
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.is_empty() || raw.contains(['\r', '\n', '\0']) {
            return Err(format!("{label} contains invalid characters"));
        }
        return Ok(raw.to_owned());
    }
    if flags.boolean(&stdin_key) {
        let mut line = String::new();
        std::io::BufReader::new(std::io::stdin().take(4097))
            .read_line(&mut line)
            .map_err(|e| format!("read {label} from stdin: {e}"))?;
        let value = line.trim_end_matches(['\r', '\n']);
        if value.is_empty() {
            return Err(format!("{label} from stdin is empty"));
        }
        if value.len() > 4096 {
            return Err(format!("{label} from stdin exceeds 4096 bytes"));
        }
        return Ok(value.to_owned());
    }
    Ok(String::new())
}
pub fn go_io_error(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".into(),
        std::io::ErrorKind::PermissionDenied => "permission denied".into(),
        _ => {
            if e.raw_os_error().is_some() {
                e.to_string()
                    .split(" (os error")
                    .next()
                    .unwrap()
                    .to_lowercase()
            } else {
                e.to_string()
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct Definition {
    flags: BTreeMap<String, String>,
    mode: String,
    help: String,
    override_error: Option<String>,
    status: Option<i32>,
}
fn definitions() -> &'static BTreeMap<String, Definition> {
    static DEFINITIONS: std::sync::OnceLock<BTreeMap<String, Definition>> =
        std::sync::OnceLock::new();
    DEFINITIONS.get_or_init(|| {
        let mut definitions: BTreeMap<String, Definition> =
            serde_json::from_str(include_str!("flags_b.json")).expect("recorded flag definitions");
        definitions.extend(
            serde_json::from_str::<BTreeMap<String, Definition>>(include_str!("flags_c.json"))
                .expect("recorded local flag definitions"),
        );
        definitions
    })
}
fn parse_integer(raw: &str) -> Result<i64, &'static str> {
    let negative = raw.starts_with('-');
    let s = raw.strip_prefix(['+', '-']).unwrap_or(raw);
    let (radix, s, prefix) = if s.starts_with("0x") || s.starts_with("0X") {
        (16, &s[2..], true)
    } else if s.starts_with("0o") || s.starts_with("0O") {
        (8, &s[2..], true)
    } else if s.starts_with("0b") || s.starts_with("0B") {
        (2, &s[2..], true)
    } else if s.starts_with('0') && s.len() > 1 {
        (8, &s[1..], true)
    } else {
        (10, s, false)
    };
    if s.is_empty() {
        return Err("parse error");
    }
    let mut magnitude = 0u128;
    let mut prev_digit = false;
    for (i, c) in s.chars().enumerate() {
        if c == '_' {
            if (!prev_digit && !(i == 0 && prefix)) || i + 1 == s.len() {
                return Err("parse error");
            }
            prev_digit = false;
            continue;
        }
        let d = c.to_digit(radix).ok_or("parse error")?;
        magnitude = magnitude
            .checked_mul(radix as u128)
            .and_then(|n| n.checked_add(d as u128))
            .ok_or("value out of range")?;
        prev_digit = true;
    }
    if magnitude > i64::MAX as u128 + u128::from(negative) {
        return Err("value out of range");
    }
    Ok(if negative {
        if magnitude == 1u128 << 63 {
            i64::MIN
        } else {
            -(magnitude as i64)
        }
    } else {
        magnitude as i64
    })
}
