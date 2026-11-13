//! Operator backup and restore processes. Privileged credentials never enter argv.
mod recovery;
use crate::{client::Failure, flags};
use setjoin_backup::{store::Store, TempFile};
use std::{
    path::Path,
    process::{Command, Stdio},
};
fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}
fn field(f: &flags::Flags, k: &str, env_key: &str) -> String {
    if f.set(k) {
        f.get(k).into()
    } else {
        env(env_key)
    }
}
fn owner_dsn(flag: &str) -> String {
    if !flag.is_empty() {
        flag.into()
    } else {
        [
            "DB_DIRECT_OWNER_DSN",
            "DB_OWNER_DSN",
            "DB_DIRECT_DSN",
            "DB_DSN",
        ]
        .iter()
        .map(|k| env(k))
        .find(|s| !s.is_empty())
        .unwrap_or_default()
    }
}
const DSN_REFUSE:&str="DSN embeds credentials in a form that cannot be safely stripped; pass a credential-free DSN and deliver the password via PGPASSWORD or a 0600 .pgpass instead";
fn loose_password(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.match_indices("password").any(|(i, _)| {
        (i == 0
            || !lower.as_bytes()[i - 1].is_ascii_alphanumeric() && lower.as_bytes()[i - 1] != b'_')
            && lower[i + 8..]
                .trim_start_matches(|c: char| c.is_ascii_whitespace())
                .starts_with('=')
    })
}
fn split_dsn(raw: &str) -> Result<(String, String), String> {
    if raw.contains("://") {
        let mut u = match url::Url::parse(raw) {
            Ok(u) => u,
            Err(_) => {
                let auth = raw
                    .split_once("://")
                    .unwrap()
                    .1
                    .split_once('@')
                    .map(|(a, _)| a)
                    .unwrap_or("");
                return if auth.contains(':') || loose_password(raw) {
                    Err(DSN_REFUSE.into())
                } else {
                    Ok((raw.into(), String::new()))
                };
            }
        };
        let inline = u.password().is_some();
        let mut pw = u.password().map(url_decode).unwrap_or_default();
        let mut pairs = vec![];
        let mut passwords = vec![];
        for (k, v) in u.query_pairs() {
            if k == "password" {
                passwords.push(v.to_string());
            } else {
                pairs.push((k.to_string(), v.to_string()));
            }
        }
        if passwords.len() > 1 {
            return Err(
                "DSN carries multiple ?password= parameters; pass a single credential source"
                    .into(),
            );
        }
        if let Some(query) = passwords.first().filter(|s| !s.is_empty()) {
            if !pw.is_empty() && pw != *query {
                return Err("DSN carries two different passwords (userinfo and query parameter); pass a single credential source".into());
            }
            pw = query.clone();
        }
        if pw.is_empty() && passwords.is_empty() {
            if inline || loose_password(raw) {
                return Err(DSN_REFUSE.into());
            }
            return Ok((raw.into(), String::new()));
        }
        u.set_password(None).map_err(|_| DSN_REFUSE)?;
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        u.set_query(None);
        if !pairs.is_empty() {
            u.query_pairs_mut().extend_pairs(pairs);
        }
        let clean = u.to_string();
        if loose_password(&clean) {
            return Err("resolved DSN still embeds credentials after stripping; refusing to place a password in pg_dump/pg_restore argv (deliver credentials via PGPASSWORD or a 0600 .pgpass instead)".into());
        }
        return Ok((clean, pw));
    }
    if !raw.contains('=') {
        return Ok((raw.into(), String::new()));
    }
    let bytes = raw.as_bytes();
    let mut i = 0;
    let mut kept = vec![];
    let mut pw = String::new();
    let mut found = false;
    let error =
        |s: &str| format!("DSN embeds credentials in a form that cannot be safely stripped: {s}");
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let keyword = &raw[start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if keyword.is_empty() || bytes.get(i) != Some(&b'=') {
            return Err(error(
                "malformed keyword/value conninfo (missing '=' after keyword)",
            ));
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let quoted = bytes.get(i) == Some(&b'\'');
        if quoted {
            i += 1;
        }
        let mut value = vec![];
        let mut closed = !quoted;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'\\' {
                i += 1;
                if i == bytes.len() {
                    return Err(error("unterminated backslash escape"));
                }
                value.push(bytes[i]);
                i += 1;
                continue;
            }
            if quoted && b == b'\'' {
                i += 1;
                if bytes.get(i) == Some(&b'\'') {
                    value.push(b'\'');
                    i += 1;
                    continue;
                }
                closed = true;
                break;
            }
            if !quoted && b.is_ascii_whitespace() {
                break;
            }
            value.push(b);
            i += 1;
        }
        if !closed {
            return Err(error("unterminated quoted value"));
        }
        if keyword.eq_ignore_ascii_case("password") {
            pw = String::from_utf8_lossy(&value).into_owned();
            found = true;
        } else {
            kept.push(&raw[start..i]);
        }
    }
    let clean = if found { kept.join(" ") } else { raw.into() };
    if loose_password(&clean) {
        return Err(DSN_REFUSE.into());
    }
    Ok((clean, pw))
}
fn url_decode(s: &str) -> String {
    let fake = format!("x={}", s.replace('+', "%2B"));
    url::form_urlencoded::parse(fake.as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}
fn credentials(f: &flags::Flags) -> Result<(String, String), Failure> {
    let raw = owner_dsn(f.get("dsn"));
    if f.set("dsn") && split_dsn(&raw).map_or(true, |(clean, p)| !p.is_empty() || clean != raw) {
        return Err("--dsn with embedded credentials must not be passed on the command line (process listings and shell history expose it); export DB_DIRECT_OWNER_DSN / DB_OWNER_DSN instead".into());
    }
    let (dsn, password) = split_dsn(&raw)?;
    Ok((
        dsn,
        if password.is_empty() {
            env("PGPASSWORD")
        } else {
            password
        },
    ))
}
fn private_file(path: &str, label: &str, min: u64, max: u64) -> Result<Vec<u8>, Failure> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::symlink_metadata(path)
        .map_err(|e| format!("read {label}: lstat {path}: {}", flags::go_io_error(&e)))?;
    if !m.is_file() || m.permissions().mode() & 0o077 != 0 || m.len() < min || m.len() > max {
        return Err(format!(
            "{label} must be a regular non-symlink 0600 file of {min}-{max} bytes"
        )
        .into());
    }
    std::fs::read(path)
        .map_err(|e| format!("read {label}: open {path}: {}", flags::go_io_error(&e)).into())
}
fn credential_file(path: &str, label: &str) -> Result<String, Failure> {
    let raw = private_file(path, label, 1, 4096)?;
    let raw = String::from_utf8_lossy(&raw);
    let value = raw.strip_suffix('\n').unwrap_or(&raw);
    let value = value.strip_suffix('\r').unwrap_or(value);
    if value.is_empty() || value.contains(['\r', '\n', '\0']) {
        return Err(format!("{label} contains invalid characters").into());
    }
    Ok(value.into())
}
struct Config {
    dsn: String,
    password: String,
    bucket: String,
    store: Store,
    key: Vec<u8>,
}
fn config(f: &flags::Flags) -> Result<Config, Failure> {
    for k in ["access-key", "secret-key"] {
        if f.set(k) {
            return Err(format!("--{k} must not be passed on the command line (process listings and shell history expose it); pass the matching --{k}-file (0600) or set the environment default instead").into());
        }
    }
    let (dsn, password) = credentials(f)?;
    let mut access = env("BACKUP_ACCESS_KEY");
    let mut secret = env("BACKUP_SECRET_KEY");
    let access_file = field(f, "access-key-file", "BACKUP_ACCESS_KEY_FILE");
    let secret_file = field(f, "secret-key-file", "BACKUP_SECRET_KEY_FILE");
    let bucket = f.get("bucket");
    if bucket.is_empty()
        || (access.is_empty() && access_file.is_empty())
        || (secret.is_empty() && secret_file.is_empty())
    {
        return Err(
            "backup bucket and access/secret credentials (prefer 0600 files) are required".into(),
        );
    }
    if !access_file.is_empty() {
        access = credential_file(&access_file, "backup access key")?;
    }
    if !secret_file.is_empty() {
        secret = credential_file(&secret_file, "backup secret key")?;
    }
    if dsn.is_empty() {
        return Err(
            "no DSN: pass --dsn or set DB_DIRECT_OWNER_DSN / DB_OWNER_DSN / DB_DIRECT_DSN / DB_DSN"
                .into(),
        );
    }
    let path = field(f, "dump-hmac-key-file", "BACKUP_DUMP_HMAC_KEY_FILE");
    if path.is_empty() {
        return Err("dump authentication is mandatory at publication: pass --dump-hmac-key-file (or set BACKUP_DUMP_HMAC_KEY_FILE) so restore can verify the dump fail-closed before pg_restore runs".into());
    }
    let key = private_file(&path, "dump authentication HMAC key", 32, 16384)?;
    Ok(Config {
        dsn,
        password,
        bucket: bucket.into(),
        store: Store::new(f.get("endpoint"), f.get("region"), bucket, &access, &secret)?,
        key,
    })
}
fn binary(name: &str) -> Result<(), Failure> {
    if std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .any(|p| p.join(name).is_file())
    {
        Ok(())
    } else {
        Err(format!(
            "{name} binary not found in PATH: exec: {name:?}: executable file not found in $PATH"
        )
        .into())
    }
}
fn pg_command(name: &str, password: &str) -> Command {
    let mut cmd = Command::new(name);
    if !password.is_empty() {
        cmd.env("PGPASSWORD", password);
    }
    cmd
}
fn validate_dump(path: &Path) -> Result<(), Failure> {
    let result = Command::new("pg_restore")
        .arg("--list")
        .arg(path)
        .stdout(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if result.status.success() {
        Ok(())
    } else {
        Err(format!(
            "pg_restore --list rejected the completed dump: exit status {}: {}",
            result.status.code().unwrap_or(1),
            String::from_utf8_lossy(&result.stderr[..result.stderr.len().min(4096)])
        )
        .into())
    }
}
pub fn run(cmd: &str, args: &[String]) -> Result<(), Failure> {
    if cmd != "backup-db" {
        return restore(args);
    }
    let f = flags::parse(
        "backup-db",
        args,
        &[
            "dsn",
            "provider",
            "endpoint",
            "region",
            "bucket",
            "access-key",
            "secret-key",
            "access-key-file",
            "secret-key-file",
            "dump-hmac-key-file",
        ],
        &[],
        false,
    );
    let cfg = config(&f)?;
    binary("pg_dump")?;
    binary("pg_restore")?;
    let tmp = TempFile::new("mailctl-db-dump-", ".dump")?;
    eprintln!("Running pg_dump (custom format)...");
    let result = pg_command("pg_dump", &cfg.password)
        .arg("--format=custom")
        .arg(format!("--file={}", tmp.path.display()))
        .arg(&cfg.dsn)
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| e.to_string())?;
    if !result.success() {
        return Err(format!("pg_dump failed: exit status {}", result.code().unwrap_or(1)).into());
    }
    validate_dump(&tmp.path)?;
    let size = std::fs::metadata(&tmp.path)
        .map_err(|e| e.to_string())?
        .len();
    if size == 0 {
        return Err("pg_dump produced an empty custom-format dump".into());
    }
    eprintln!(
        "Dump complete ({size} bytes). Uploading to s3://{} ...",
        cfg.bucket
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async{let archive=format!("db-dump-{}.dump",chrono::Utc::now().format("%Y%m%dT%H%M%SZ"));for name in ["db-dump.dump",&archive]{let sidecar=setjoin_backup::seal_dump(&tmp.path,name,&cfg.key)?;cfg.store.put_file(name,&tmp.path).await?;cfg.store.put(&format!("{name}.hmac"),sidecar).await?;}println!("Backup uploaded: s3://{}/db-dump.dump (+db-dump.dump.hmac)\nArchival copy:   s3://{}/{} (+{}.hmac)",cfg.bucket,cfg.bucket,archive,archive);Ok::<_,Failure>(())})
}

#[derive(serde::Serialize)]
struct RestoreRequest {
    provider: String,
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    #[serde(rename = "type")]
    typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<String>>,
}
struct RestoreConfig {
    request: RestoreRequest,
    dsn: String,
    password: String,
    key: Vec<u8>,
    socket: String,
    dry: bool,
    yes: bool,
}
fn restore_config(args: &[String]) -> Result<RestoreConfig, Failure> {
    let f = flags::parse(
        "restore",
        args,
        &[
            "provider",
            "endpoint",
            "region",
            "bucket",
            "access-key",
            "secret-key",
            "access-key-file",
            "secret-key-file",
            "type",
            "hashes",
            "control-socket",
            "dsn",
            "dump-hmac-key-file",
        ],
        &["dry-run", "yes"],
        false,
    );
    for k in ["access-key", "secret-key"] {
        if f.set(k) {
            return Err(format!("--{k} must not be passed on the command line (process listings and shell history expose it); pass the matching --{k}-file (0600) or set the environment default instead").into());
        }
    }
    let typ = if f.set("type") { f.get("type") } else { "full" };
    if !matches!(typ, "full" | "config" | "blobs") {
        return Err(format!("invalid --type {typ:?}: must be full, config, or blobs").into());
    }
    let (dsn, password) = credentials(&f)?;
    let mut access = env("BACKUP_ACCESS_KEY");
    let mut secret = env("BACKUP_SECRET_KEY");
    let access_file = field(&f, "access-key-file", "BACKUP_ACCESS_KEY_FILE");
    let secret_file = field(&f, "secret-key-file", "BACKUP_SECRET_KEY_FILE");
    let bucket = f.get("bucket");
    if bucket.is_empty()
        || (access.is_empty() && access_file.is_empty())
        || (secret.is_empty() && secret_file.is_empty())
    {
        return Err(
            "backup bucket and access/secret credentials (prefer 0600 files) are required".into(),
        );
    }
    if !access_file.is_empty() {
        access = credential_file(&access_file, "backup access key")?;
    }
    if !secret_file.is_empty() {
        secret = credential_file(&secret_file, "backup secret key")?;
    }
    let mut socket = field(&f, "control-socket", "SETJOIN_CONTROL_SOCKET")
        .trim()
        .to_owned();
    if socket.is_empty() {
        socket = "/run/setjoin/control.sock".into();
    }
    if !socket.starts_with('/') {
        return Err("--control-socket must be an absolute path".into());
    }
    let mut key = vec![];
    if typ == "full" && !f.boolean("dry-run") {
        if dsn.is_empty() {
            return Err("type=full restore needs a DSN for pg_restore: pass --dsn or set DB_DIRECT_OWNER_DSN / DB_OWNER_DSN / DB_DIRECT_DSN / DB_DSN".into());
        }
        let path = field(&f, "dump-hmac-key-file", "BACKUP_DUMP_HMAC_KEY_FILE");
        if path.is_empty() {
            return Err("type=full restore authenticates the dump before pg_restore may run: pass --dump-hmac-key-file or set BACKUP_DUMP_HMAC_KEY_FILE (the key backup-db sealed the dump's sidecar under)".into());
        }
        key = private_file(&path, "dump authentication HMAC key", 32, 16384)?;
    }
    let hashes = f
        .get("hashes")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Ok(RestoreConfig {
        request: RestoreRequest {
            provider: f.get("provider").into(),
            endpoint: f.get("endpoint").into(),
            region: f.get("region").into(),
            bucket: bucket.into(),
            access_key: access,
            secret_key: secret,
            typ: typ.into(),
            hashes: if hashes.is_empty() {
                None
            } else {
                Some(hashes)
            },
        },
        dsn,
        password,
        key,
        socket,
        dry: f.boolean("dry-run"),
        yes: f.boolean("yes"),
    })
}
fn control(
    cfg: &RestoreConfig,
    path: &str,
    request: &RestoreRequest,
) -> Result<serde_json::Value, Failure> {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .unix_socket(Path::new(&cfg.socket))
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(1800))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .post(format!("http://setjoin-control{path}"))
        .header("Content-Type", "application/json")
        .body(setjoin_backup::json(request))
        .send()
        .map_err(|e| format!("POST {path}: {e}"))?;
    let status = response.status().as_u16();
    let body = response.text().map_err(|e| e.to_string())?;
    if status >= 400 {
        return Err(format!("gateway returned HTTP {status}: {}", body.trim()).into());
    }
    serde_json::from_str(&body).map_err(|e| {
        format!(
            "decode response: {}",
            crate::client::json_error(&body, &e, true)
        )
        .into()
    })
}
fn restore(args: &[String]) -> Result<(), Failure> {
    let cfg = restore_config(args)?;
    if cfg.dry {
        // Hash filters apply only to the restore call, never the preflight body.
        let request = RestoreRequest {
            provider: cfg.request.provider.clone(),
            endpoint: cfg.request.endpoint.clone(),
            region: cfg.request.region.clone(),
            bucket: cfg.request.bucket.clone(),
            access_key: cfg.request.access_key.clone(),
            secret_key: cfg.request.secret_key.clone(),
            typ: cfg.request.typ.clone(),
            hashes: None,
        };
        let v = control(&cfg, "/setup/preflight", &request)?;
        let text = |k: &str| v[k].as_str().unwrap_or("");
        let number = |k: &str| v[k].as_i64().unwrap_or(0);
        println!("Backup preview\n  Timestamp:    {}\n  Users:        {}\n  Domains:      {}\n  Config size:  {} bytes\n  Blobs:        {} ({} bytes total)",text("timestamp"),number("user_count"),number("domain_count"),number("config_size_bytes"),number("blob_count"),number("blob_total_size_bytes"));
        if let Some(warnings) = v["warnings"].as_array().filter(|a| !a.is_empty()) {
            println!("  Warnings:");
            for w in warnings {
                println!("    - {}", w.as_str().unwrap_or(""));
            }
        }
        return Ok(());
    }
    if !cfg.yes {
        use std::io::Write;
        print!("This is a DESTRUCTIVE restore and will overwrite the target system.\nType RESTORE to confirm: ");
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if line.trim() != "RESTORE" {
            return Err("restore aborted: confirmation not given".into());
        }
    }
    let full = cfg.request.typ == "full";
    let v = if full {
        let request = RestoreRequest {
            provider: cfg.request.provider.clone(),
            endpoint: cfg.request.endpoint.clone(),
            region: cfg.request.region.clone(),
            bucket: cfg.request.bucket.clone(),
            access_key: cfg.request.access_key.clone(),
            secret_key: cfg.request.secret_key.clone(),
            typ: "blobs".into(),
            hashes: None,
        };
        let v = control(&cfg, "/setup/restore", &request)?;
        eprintln!("Re-checking empty target and replacing preloaded public schema...");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        rt.block_on(async{
            let mut db=setjoin_pg::operator::OperatorConnection::connect_password(&cfg.dsn,&cfg.password).await.map_err(|e|format!("connect for restore schema reset: {e}"))?;
            db.reset_empty_for_restore().await?;drop(db);binary("pg_restore")?;
            let tmp=TempFile::new("mailctl-db-restore-",".dump")?;
            let store=Store::new(&request.endpoint,&request.region,&request.bucket,&request.access_key,&request.secret_key)?;
            eprintln!("Downloading s3://{}/db-dump.dump ...",request.bucket);store.get_file("db-dump.dump",&tmp.path).await?;
            eprintln!("Downloading s3://{}/db-dump.dump.hmac ...",request.bucket);
            let sidecar=store.get("db-dump.dump.hmac",1<<20).await.map_err(|e|format!("dump authentication sidecar unavailable (a dump without its published authentication binding is refused): {e}"))?;
            setjoin_backup::verify_dump(&tmp.path,"db-dump.dump",&cfg.key,&sidecar).map_err(|e|format!("refusing to restore: {e}"))?;
            eprintln!("Running pg_restore (--clean --if-exists)...");
            let status=pg_command("pg_restore",&cfg.password).arg("--clean").arg("--if-exists").arg(format!("--dbname={}",cfg.dsn)).arg(&tmp.path).stdout(Stdio::from(std::io::stderr())).stderr(Stdio::inherit()).status().map_err(|e|e.to_string())?;
            if !status.success(){return Err(Failure::from(format!("pg_restore failed: exit status {}",status.code().unwrap_or(1))));}Ok::<_,Failure>(())
        })?;
        v
    } else {
        control(&cfg, "/setup/restore", &cfg.request)?
    };
    println!(
        "Restore {} (job {})\n  Blobs restored:       {}",
        v["status"].as_str().unwrap_or(""),
        v["restore_job_id"].as_i64().unwrap_or(0),
        v["restored_blobs"].as_i64().unwrap_or(0)
    );
    if full {
        println!("  Database + config:    restored via pg_restore");
    } else {
        println!(
            "  Config keys restored: {}",
            v["restored_config_keys"].as_i64().unwrap_or(0)
        );
    }
    if let Some(errors) = v["errors"].as_array().filter(|a| !a.is_empty()) {
        eprintln!("Restore completed with {} error(s):", errors.len());
        for e in errors {
            eprintln!("  - {}", e.as_str().unwrap_or(""));
        }
        return Err(format!("restore reported {} error(s)", errors.len()).into());
    }
    Ok(())
}

pub(super) fn api(
    api: &crate::client::Api,
    options: &crate::Options,
    action: &str,
    args: &[String],
) -> Result<(), Failure> {
    match action {
        "run" => {
            api.request("POST", "/admin/system/backup", None, true)?;
            Ok(())
        }
        "list" => {
            options.list(&api.request("GET", "/admin/system/backup/list", None, true)?);
            Ok(())
        }
        "create" | "verify" => recovery::run(api, options, action, args),
        _ => {
            Err(format!("unknown backup action: {action} (try: run, list, create, verify)").into())
        }
    }
}
