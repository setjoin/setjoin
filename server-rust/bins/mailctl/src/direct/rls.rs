//! `mailctl schema preflight` and `mailctl schema provision-roles` (#545, Wave 1.7).

use setjoin_pg::operator::OperatorConnection;
use setjoin_pg::rls_preflight::{
    dsn_username, extract_dsn_password, inspect_rls_posture_operator,
    provision_roles_and_verify_operator, redact_dsn, rewrite_dsn_credentials,
    set_role_login_password, DsnRoleSummary, EnforcementMode, PostureContext, RlsPreflightReport,
};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn resolve_owner_dsn() -> Result<String, String> {
    for key in [
        "DB_DIRECT_OWNER_DSN",
        "DB_OWNER_DSN",
        "DB_DIRECT_DSN",
        "DB_DSN",
    ] {
        if let Some(dsn) = env_nonempty(key) {
            return Ok(dsn);
        }
    }
    Err("DB_DIRECT_OWNER_DSN, DB_OWNER_DSN, DB_DIRECT_DSN or DB_DSN environment variable is required".to_owned())
}

fn random_hex_24() -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 24];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "CSPRNG password generation failed".to_owned())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub async fn preflight(args: &[String]) -> Result<i32, String> {
    let fs = crate::flags::parse("schema preflight", args, &[], &["json"], false);
    let has_owner_dsn =
        env_nonempty("DB_DIRECT_OWNER_DSN").is_some() || env_nonempty("DB_OWNER_DSN").is_some();
    let connect_dsn = resolve_owner_dsn()?;
    let db = OperatorConnection::connect(&connect_dsn)
        .await
        .map_err(|e| {
            format!(
                "connecting to database ({}): {}",
                redact_dsn(&connect_dsn),
                redact_dsn(&e)
            )
        })?;
    let dsn_roles = DsnRoleSummary::from_dsns(
        env_nonempty("DB_DSN").as_deref(),
        env_nonempty("DB_WORKER_DSN").as_deref(),
        env_nonempty("DB_OWNER_DSN")
            .or_else(|| env_nonempty("DB_DIRECT_OWNER_DSN"))
            .as_deref(),
    );
    let context = if has_owner_dsn {
        PostureContext::OperatorOwner
    } else {
        PostureContext::RuntimeApp
    };
    let report = inspect_rls_posture_operator(&db, context, Some(dsn_roles)).await?;
    let code = report.exit_code(EnforcementMode::WarnReleaseN);
    if fs.boolean("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        print_human_report(&report);
    }
    Ok(code)
}

pub fn print_human_report(report: &RlsPreflightReport) {
    println!(
        "PostgreSQL: {} (server_version_num={}, CVE-2026-14666: {})",
        report.server_version,
        report.server_version_num,
        if report.pg_version_ok { "ok" } else { "WARN" }
    );
    println!(
        "Connected role: {} (superuser={}, bypassrls={})",
        report.current_role.name, report.current_role.rolsuper, report.current_role.rolbypassrls
    );
    for role in &report.roles {
        let status = if !role.exists {
            "MISSING"
        } else if !role.attributes_ok {
            "DRIFTED"
        } else {
            "ok"
        };
        println!(
            "  role {:<16} status={:<8} login={} bypassrls={} superuser={}",
            role.name, status, role.rolcanlogin, role.rolbypassrls, role.rolsuper
        );
    }
    println!(
        "  owner->worker membership: {}",
        if report.owner_has_worker_membership {
            "ok"
        } else {
            "MISSING"
        }
    );
    if !report.hard_errors.is_empty() {
        println!("HARD ERRORS:");
        for err in &report.hard_errors {
            println!("  [ERROR] {err}");
        }
    }
    if !report.warnings.is_empty() {
        println!("WARNINGS (Release N advisory; Release N+1 will refuse to start):");
        for warn in &report.warnings {
            println!("  [WARN] {warn}");
        }
    }
    if report.is_clean() {
        println!("RLS preflight: CLEAN");
    }
}

pub async fn advisory_check(db: &OperatorConnection) -> Option<RlsPreflightReport> {
    let has_owner_dsn =
        env_nonempty("DB_DIRECT_OWNER_DSN").is_some() || env_nonempty("DB_OWNER_DSN").is_some();
    let dsn_roles = DsnRoleSummary::from_dsns(
        env_nonempty("DB_DSN").as_deref(),
        env_nonempty("DB_WORKER_DSN").as_deref(),
        env_nonempty("DB_OWNER_DSN")
            .or_else(|| env_nonempty("DB_DIRECT_OWNER_DSN"))
            .as_deref(),
    );
    let context = if has_owner_dsn {
        PostureContext::OperatorOwner
    } else {
        PostureContext::RuntimeApp
    };
    inspect_rls_posture_operator(db, context, Some(dsn_roles))
        .await
        .ok()
}

pub async fn provision_roles(args: &[String]) -> Result<i32, String> {
    let fs = crate::flags::parse(
        "schema provision-roles",
        args,
        &["config-dir"],
        &["write-dsns", "rotate-passwords", "yes", "y", "json"],
        false,
    );
    let write_dsns = fs.boolean("write-dsns");
    let rotate_passwords = fs.boolean("rotate-passwords");
    let json_out = fs.boolean("json");
    let yes = fs.boolean("yes") || fs.boolean("y");

    validate_provision_flags(write_dsns, rotate_passwords)?;

    let config_dir = if !fs.get("config-dir").is_empty() {
        PathBuf::from(fs.get("config-dir"))
    } else if let Some(env_dir) = env_nonempty("SETJOIN_CONFIG_DIR") {
        PathBuf::from(env_dir)
    } else {
        PathBuf::from("/etc/setjoin")
    };
    let updater_dir = env_nonempty("UPDATER_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/setjoin-updater"));

    // Refuse out-of-sync password rotation before mutating DB or files if the
    // root-owned updater credential files exist on host.
    if rotate_passwords {
        check_updater_sync_guard(&updater_dir)?;
    }

    if write_dsns {
        validate_deploy004_namespace(&config_dir)?;
    }

    if !yes {
        let opts = crate::Options {
            json: json_out,
            quiet: false,
            yes: false,
        };
        let prompt = if rotate_passwords {
            "provision native-RLS roles, rotate role passwords, and update DSN config files"
        } else if write_dsns {
            "provision native-RLS roles and write least-privilege DSN config files"
        } else {
            "provision native-RLS roles and grants in PostgreSQL"
        };
        opts.confirm(prompt).map_err(|_| "aborted".to_owned())?;
    }

    let owner_dsn = resolve_owner_dsn()?;
    let direct_owner_dsn = env_nonempty("DB_DIRECT_OWNER_DSN")
        .or_else(|| env_nonempty("DB_DIRECT_DSN"))
        .unwrap_or_else(|| owner_dsn.clone());
    let mut db = OperatorConnection::connect(&owner_dsn).await.map_err(|e| {
        format!(
            "connecting to database ({}): {}",
            redact_dsn(&owner_dsn),
            redact_dsn(&e)
        )
    })?;

    // Inspect pg_roles existence BEFORE running Pass 1 (T3: non-superuser CREATEROLE
    // compatibility and pre-existing role password preservation).
    let pre = inspect_rls_posture_operator(&db, PostureContext::OperatorOwner, None).await?;
    let mut preexisting: BTreeMap<String, (bool, Option<bool>)> = BTreeMap::new();
    for r in &pre.roles {
        preexisting.insert(r.name.clone(), (r.exists, r.has_password));
    }

    let prov = provision_roles_and_verify_operator(&mut db, None).await?;

    let mut written_files: Vec<String> = Vec::new();
    let mut rotated_roles: Vec<String> = Vec::new();
    let mut preserved_roles: Vec<String> = Vec::new();

    if write_dsns {
        let base_pooled = env_nonempty("DB_OWNER_DSN").unwrap_or_else(|| owner_dsn.clone());
        let base_direct = direct_owner_dsn.clone();

        let existing_cfg = read_env_map_nofollow(&config_dir.join("config.env"))?;
        let existing_cred = read_env_map_nofollow(
            &config_dir
                .join("db-credentials.d")
                .join("db-credentials.env"),
        )?;

        let recovered_app_pw = existing_cfg
            .get("DB_DSN")
            .filter(|d| dsn_username(d).as_deref() == Some("setjoin_app"))
            .and_then(|d| extract_dsn_password(d));
        let recovered_worker_pw = existing_cred
            .get("DB_WORKER_DSN")
            .or_else(|| existing_cfg.get("DB_WORKER_DSN"))
            .filter(|d| dsn_username(d).as_deref() == Some("setjoin_worker"))
            .and_then(|d| extract_dsn_password(d));

        let app_pw = resolve_or_provision_role_password(
            &mut db,
            "setjoin_app",
            &base_pooled,
            preexisting
                .get("setjoin_app")
                .copied()
                .unwrap_or((false, None)),
            recovered_app_pw,
            rotate_passwords,
            &mut rotated_roles,
            &mut preserved_roles,
        )
        .await?;

        let worker_pw = resolve_or_provision_role_password(
            &mut db,
            "setjoin_worker",
            &base_pooled,
            preexisting
                .get("setjoin_worker")
                .copied()
                .unwrap_or((false, None)),
            recovered_worker_pw,
            rotate_passwords,
            &mut rotated_roles,
            &mut preserved_roles,
        )
        .await?;

        let runtime_app_dsn = rewrite_dsn_credentials(&base_pooled, "setjoin_app", &app_pw)?;
        let runtime_direct_dsn = rewrite_dsn_credentials(&base_direct, "setjoin_app", &app_pw)?;
        let runtime_worker_dsn =
            rewrite_dsn_credentials(&base_pooled, "setjoin_worker", &worker_pw)?;

        // Pre-cutover live login probes: prove BOTH roles authenticate before
        // touching any config file on disk.
        probe_role_login(&runtime_app_dsn, "setjoin_app").await?;
        probe_role_login(&runtime_worker_dsn, "setjoin_worker").await?;

        written_files = write_split_dsn_files(
            &config_dir,
            &runtime_app_dsn,
            &runtime_direct_dsn,
            &runtime_worker_dsn,
            &base_pooled,
            &base_direct,
        )?;
    }

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ok",
                "pass1_executed": prov.pass1_executed,
                "pass1_attempts": prov.pass1_attempts,
                "pass2_executed": prov.pass2_executed,
                "scope_helpers_repaired": prov.scope_helpers_repaired,
                "rotated_roles": rotated_roles,
                "preserved_roles": preserved_roles,
                "written_files": written_files,
                "pg_version_ok": prov.verified.pg_version_ok,
                "server_version": prov.verified.server_version,
            }))
            .map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "Provisioned native-RLS roles and grants (pass1={}, pass2={}, scope_helpers_repaired={}).",
            if prov.pass1_executed {
                "applied"
            } else {
                "verified-only"
            },
            if prov.pass2_executed { "applied" } else { "skipped" },
            prov.scope_helpers_repaired.len()
        );
        if !rotated_roles.is_empty() {
            println!("  Passwords set/rotated for: {}", rotated_roles.join(", "));
        }
        if !preserved_roles.is_empty() {
            println!("  Passwords preserved for: {}", preserved_roles.join(", "));
        }
        for path in &written_files {
            println!("  Updated {path}");
        }
    }

    Ok(0)
}

#[allow(clippy::too_many_arguments)]
async fn resolve_or_provision_role_password(
    db: &mut OperatorConnection,
    role: &str,
    base_dsn: &str,
    pre_state: (bool, Option<bool>),
    recovered_pw: Option<String>,
    rotate: bool,
    rotated_roles: &mut Vec<String>,
    preserved_roles: &mut Vec<String>,
) -> Result<String, String> {
    let (preexisted, has_password) = pre_state;
    if rotate || !preexisted {
        let pw = random_hex_24()?;
        set_role_login_password(db, role, &pw).await?;
        rotated_roles.push(role.to_owned());
        return Ok(pw);
    }
    if let Some(pw) = recovered_pw {
        let candidate = rewrite_dsn_credentials(base_dsn, role, &pw)?;
        if probe_role_login(&candidate, role).await.is_ok() {
            preserved_roles.push(role.to_owned());
            return Ok(pw);
        }
        if has_password == Some(false) {
            set_role_login_password(db, role, &pw).await?;
            rotated_roles.push(role.to_owned());
            return Ok(pw);
        }
        return Err(format!(
            "recovered password for existing role {role:?} failed live login probe; refusing to overwrite without --rotate-passwords"
        ));
    }
    if has_password == Some(false) {
        let pw = random_hex_24()?;
        set_role_login_password(db, role, &pw).await?;
        rotated_roles.push(role.to_owned());
        return Ok(pw);
    }
    Err(format!(
        "role {role:?} already exists without an env-recovered password; refusing to overwrite without --rotate-passwords"
    ))
}

async fn probe_role_login(dsn: &str, expected_role: &str) -> Result<(), String> {
    let conn = OperatorConnection::connect(dsn).await.map_err(|e| {
        format!(
            "pre-cutover login probe failed for role {expected_role:?} ({}): {}",
            redact_dsn(dsn),
            redact_dsn(&e)
        )
    })?;
    let rows = conn
        .query("SELECT current_user::text", &[])
        .await
        .map_err(|e| {
            format!(
                "pre-cutover identity query failed for {expected_role:?}: {}",
                redact_dsn(&e)
            )
        })?;
    let actual: String = rows
        .first()
        .ok_or_else(|| {
            format!("pre-cutover identity query returned no rows for {expected_role:?}")
        })?
        .get(0);
    if actual != expected_role {
        return Err(format!(
            "pre-cutover login probe connected as {actual:?}, expected {expected_role:?}"
        ));
    }
    Ok(())
}

fn validate_provision_flags(write_dsns: bool, rotate_passwords: bool) -> Result<(), String> {
    if rotate_passwords && !write_dsns {
        return Err(
            "--rotate-passwords requires --write-dsns so rotated passwords are persisted to config files"
                .to_owned(),
        );
    }
    Ok(())
}

/// Refuse `--rotate-passwords` when `/etc/setjoin-updater/*-dsn` exist on host
/// so the root-only updater credential files are never left out of sync.
pub fn check_updater_sync_guard(updater_dir: &Path) -> Result<(), String> {
    let sensitive = ["updater-dsn", "app-worker-dsn", "owner-dsn"];
    let found: Vec<String> = sensitive
        .iter()
        .map(|name| updater_dir.join(name))
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .map(|p| p.display().to_string())
        .collect();
    if !found.is_empty() {
        return Err(format!(
            "refusing --rotate-passwords because host updater credential file(s) exist ({}) and would go out of sync; update them together via install.sh or refresh /etc/setjoin-updater/*-dsn before retrying",
            found.join(", ")
        ));
    }
    Ok(())
}

/// DEPLOY-004 namespace validation (symlinks, modes, ownership when root, and
/// partial privileged-DSN split refusal).
pub fn validate_deploy004_namespace(config_dir: &Path) -> Result<(), String> {
    let cred_dir = config_dir.join("db-credentials.d");
    let cred_file = cred_dir.join("db-credentials.env");
    let config_env = config_dir.join("config.env");
    let is_root = current_euid() == 0;

    for p in [
        config_dir.to_path_buf(),
        config_env.clone(),
        cred_dir.clone(),
        cred_file.clone(),
        config_dir.join("auth.env"),
        config_dir.join("federation.env"),
        config_dir.join("smtp.env"),
    ] {
        if let Ok(meta) = std::fs::symlink_metadata(&p) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "DEPLOY-004 violation: {} is a symlink — symlink plants are never trusted",
                    p.display()
                ));
            }
        }
    }

    if let Ok(meta) = std::fs::symlink_metadata(config_dir) {
        if !meta.is_dir() {
            return Err(format!(
                "DEPLOY-004 violation: {} is not a directory",
                config_dir.display()
            ));
        }
        let mode = meta.mode() & 0o777;
        if (mode & 0o022) != 0 {
            return Err(format!(
                "DEPLOY-004 violation: config directory {} has group/other write mode {:04o}; expected <= 0755",
                config_dir.display(),
                mode
            ));
        }
        if is_root && (meta.uid() != 0 || meta.gid() != 0) {
            return Err(format!(
                "DEPLOY-004 violation: config directory {} must be owned by root:root (found {}:{})",
                config_dir.display(),
                meta.uid(),
                meta.gid()
            ));
        }
    }

    if let Ok(meta) = std::fs::symlink_metadata(&cred_dir) {
        if !meta.is_dir() {
            return Err(format!(
                "DEPLOY-004 violation: {} is not a directory",
                cred_dir.display()
            ));
        }
        let mode = meta.mode() & 0o777;
        if mode != 0o750 {
            return Err(format!(
                "DEPLOY-004 violation: credential directory {} has mode {:04o}, want 0750",
                cred_dir.display(),
                mode
            ));
        }
        if is_root && meta.uid() != 0 {
            return Err(format!(
                "DEPLOY-004 violation: credential directory {} must be owned by root (uid=0, found {})",
                cred_dir.display(),
                meta.uid()
            ));
        }
    }

    if let Ok(meta) = std::fs::symlink_metadata(&cred_file) {
        if !meta.is_file() {
            return Err(format!(
                "DEPLOY-004 violation: {} is not a regular file",
                cred_file.display()
            ));
        }
        let mode = meta.mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "DEPLOY-004 violation: credential file {} has mode {:04o}, want 0600",
                cred_file.display(),
                mode
            ));
        }
        if is_root && (meta.uid() != 0 || meta.gid() != 0) {
            return Err(format!(
                "DEPLOY-004 violation: credential file {} must be owned by root:root (found {}:{})",
                cred_file.display(),
                meta.uid(),
                meta.gid()
            ));
        }
    }

    // Refuse partial split state (privileged keys in BOTH db-credentials.env and config.env).
    if cred_file.exists() && config_env.exists() {
        let cfg_map = read_env_map_nofollow(&config_env)?;
        let leaked: Vec<&str> = ["DB_WORKER_DSN", "DB_OWNER_DSN", "DB_DIRECT_OWNER_DSN"]
            .into_iter()
            .filter(|k| cfg_map.contains_key(*k))
            .collect();
        if !leaked.is_empty() {
            return Err(format!(
                "partial privileged-DSN split state: {} exists AND {} still present in {}; repair before retrying",
                cred_file.display(),
                leaked.join("/"),
                config_env.display()
            ));
        }
    }

    Ok(())
}

fn current_euid() -> u32 {
    // SAFETY: POSIX `geteuid()` has no invariants and cannot fail.
    unsafe { libc::geteuid() }
}

fn lookup_group_gid(name: &str) -> Option<u32> {
    let c_name = CString::new(name).ok()?;
    // SAFETY: `getgrnam` reads a NUL-terminated static C string; we copy `gr_gid` immediately.
    unsafe {
        let grp = libc::getgrnam(c_name.as_ptr());
        if grp.is_null() {
            None
        } else {
            Some((*grp).gr_gid)
        }
    }
}

fn read_string_nofollow(path: &Path) -> Result<Option<(String, std::fs::Metadata)>, String> {
    let mut opts = OpenOptions::new();
    opts.read(true).custom_flags(libc::O_NOFOLLOW);
    match opts.open(path) {
        Ok(mut file) => {
            let meta = file
                .metadata()
                .map_err(|e| format!("stat {}: {e}", path.display()))?;
            if !meta.is_file() {
                return Err(format!("{} is not a regular file", path.display()));
            }
            let mut buf = String::new();
            file.read_to_string(&mut buf)
                .map_err(|e| format!("reading {}: {e}", path.display()))?;
            Ok(Some((buf, meta)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("opening {} (O_NOFOLLOW): {e}", path.display())),
    }
}

fn unquote_systemd_env_value(raw: &str) -> String {
    let v = raw.trim();
    if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        v[1..v.len() - 1].to_owned()
    } else {
        v.to_owned()
    }
}

fn read_env_map_nofollow(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let Some((content, _)) = read_string_nofollow(path)? else {
        return Ok(BTreeMap::new());
    };
    let mut map = BTreeMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_owned(), unquote_systemd_env_value(v));
        }
    }
    Ok(map)
}

/// Atomic `O_CREAT|O_EXCL|O_NOFOLLOW` temp file write with exact mode,
/// optional `fchown`, `fsync`, `rename`, and parent directory `fsync`.
pub fn atomic_write_file(
    target: &Path,
    content: &[u8],
    mode: u32,
    chown_uid_gid: Option<(u32, u32)>,
) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("target path {} has no parent directory", target.display()))?;
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid target filename {}", target.display()))?;

    let mut temp_path = None;
    let mut temp_file = None;
    for attempt in 0..8u32 {
        let nonce = random_hex_24()?;
        let candidate = parent.join(format!(".{file_name}.tmp.{}.{attempt}", &nonce[..12]));
        let open_res = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&candidate);
        match open_res {
            Ok(f) => {
                temp_path = Some(candidate);
                temp_file = Some(f);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "creating atomic temp file {}: {e}",
                    candidate.display()
                ));
            }
        }
    }
    let tmp_path = temp_path.ok_or_else(|| "exhausted temp filename attempts".to_owned())?;
    let mut file = temp_file.expect("temp file opened");

    let write_res = (|| -> Result<(), String> {
        file.write_all(content)
            .map_err(|e| format!("writing {}: {e}", tmp_path.display()))?;
        if let Some((uid, gid)) = chown_uid_gid {
            let rc = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                // Non-root test runs cannot chown to another uid; only fail if root or real error.
                if current_euid() == 0 || err.kind() != std::io::ErrorKind::PermissionDenied {
                    return Err(format!("fchown {}: {err}", tmp_path.display()));
                }
            }
        }
        let rc = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
        if rc != 0 {
            return Err(format!(
                "fchmod {} to {:04o}: {}",
                tmp_path.display(),
                mode,
                std::io::Error::last_os_error()
            ));
        }
        file.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp_path.display()))?;
        Ok(())
    })();

    if let Err(e) = write_res {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(file);

    if let Err(e) = std::fs::rename(&tmp_path, target) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!(
            "atomic rename {} -> {}: {e}",
            tmp_path.display(),
            target.display()
        ));
    }

    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn update_env_lines(existing: &str, updates: &[(&str, &str)], strip_keys: &[&str]) -> String {
    let mut out_lines: Vec<String> = Vec::new();
    let mut seen: BTreeMap<&str, bool> = BTreeMap::new();
    for line in existing.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some((k, _)) = trimmed.split_once('=') {
                let key = k.trim();
                if strip_keys.contains(&key) {
                    continue;
                }
                if let Some(&(uk, uv)) = updates.iter().find(|&&(uk, _)| uk == key) {
                    if !seen.contains_key(uk) {
                        out_lines.push(format!("{uk}={uv}"));
                        seen.insert(uk, true);
                    }
                    continue;
                }
            }
        }
        out_lines.push(line.to_owned());
    }
    for &(uk, uv) in updates {
        if !seen.contains_key(uk) {
            out_lines.push(format!("{uk}={uv}"));
        }
    }
    let mut rendered = out_lines.join("\n");
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    rendered
}

/// Atomically write split `db-credentials.env`, backup + update `config.env`
/// (preserving existing `uid:gid`), and atomically sync derived env files
/// (`auth.env`, `federation.env`, `smtp.env`) when present.
pub fn write_split_dsn_files(
    config_dir: &Path,
    runtime_app_dsn: &str,
    runtime_direct_dsn: &str,
    runtime_worker_dsn: &str,
    owner_dsn: &str,
    direct_owner_dsn: &str,
) -> Result<Vec<String>, String> {
    validate_deploy004_namespace(config_dir)?;
    let is_root = current_euid() == 0;
    let setjoin_gid = lookup_group_gid("setjoin");

    std::fs::create_dir_all(config_dir)
        .map_err(|e| format!("creating {}: {e}", config_dir.display()))?;
    let cred_dir = config_dir.join("db-credentials.d");
    if !cred_dir.exists() {
        std::fs::DirBuilder::new()
            .mode(0o750)
            .create(&cred_dir)
            .map_err(|e| format!("creating {}: {e}", cred_dir.display()))?;
        let dir_fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&cred_dir)
            .map_err(|e| {
                format!(
                    "opening {} (O_NOFOLLOW|O_DIRECTORY): {e}",
                    cred_dir.display()
                )
            })?;
        let rc = unsafe { libc::fchmod(dir_fd.as_raw_fd(), 0o750) };
        if rc != 0 {
            return Err(format!(
                "fchmod 0750 {}: {}",
                cred_dir.display(),
                std::io::Error::last_os_error()
            ));
        }
        if is_root {
            let gid = setjoin_gid.unwrap_or(0);
            let rc = unsafe { libc::fchown(dir_fd.as_raw_fd(), 0, gid) };
            if rc != 0 {
                return Err(format!(
                    "fchown root:setjoin {}: {}",
                    cred_dir.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
    }

    let mut written = Vec::new();
    let config_env = config_dir.join("config.env");
    let existing_cfg = read_string_nofollow(&config_env)?;
    let root_owner = is_root.then_some((0u32, 0u32));

    // Timestamped 0600 backup of pre-cutover config.env inside root-controlled db-credentials.d.
    if let Some((ref orig_content, _)) = existing_cfg {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let backup_path = cred_dir.join(format!("config.env.pre-provision.{stamp}"));
        atomic_write_file(&backup_path, orig_content.as_bytes(), 0o600, root_owner)?;
        written.push(backup_path.display().to_string());
    }

    // Write db-credentials.d/db-credentials.env (0600 root:root).
    let cred_file = cred_dir.join("db-credentials.env");
    let cred_content = format!(
        "# setjoin privileged DB credential tier — managed by mailctl schema provision-roles.\n\
         # Mode 0600 root:root below db-credentials.d; never merged back into config.env.\n\
         DB_WORKER_DSN={runtime_worker_dsn}\n\
         DB_OWNER_DSN={owner_dsn}\n\
         DB_DIRECT_OWNER_DSN={direct_owner_dsn}\n"
    );
    atomic_write_file(&cred_file, cred_content.as_bytes(), 0o600, root_owner)?;
    written.push(cred_file.display().to_string());

    // Update config.env atomically, preserving existing uid:gid (e.g. setjoin:setjoin).
    let (cfg_src, cfg_owner) = match existing_cfg {
        Some((src, meta)) => (src, Some((meta.uid(), meta.gid()))),
        None => (String::new(), None),
    };
    let updated_cfg = update_env_lines(
        &cfg_src,
        &[
            ("DB_DSN", runtime_app_dsn),
            ("DB_DIRECT_DSN", runtime_direct_dsn),
        ],
        &["DB_WORKER_DSN", "DB_OWNER_DSN", "DB_DIRECT_OWNER_DSN"],
    );
    atomic_write_file(&config_env, updated_cfg.as_bytes(), 0o600, cfg_owner)?;
    written.push(config_env.display().to_string());

    // Atomically sync derived env files when present.
    let auth_env = config_dir.join("auth.env");
    if let Some((src, meta)) = read_string_nofollow(&auth_env)? {
        let updated = update_env_lines(&src, &[("DB_WORKER_DSN", runtime_worker_dsn)], &[]);
        let owner = if is_root {
            Some((0u32, 0u32))
        } else {
            Some((meta.uid(), meta.gid()))
        };
        atomic_write_file(&auth_env, updated.as_bytes(), 0o600, owner)?;
        written.push(auth_env.display().to_string());
    }

    for name in ["federation.env", "smtp.env"] {
        let path = config_dir.join(name);
        if let Some((src, meta)) = read_string_nofollow(&path)? {
            let updated = update_env_lines(
                &src,
                &[
                    ("DB_DSN", runtime_app_dsn),
                    ("DB_DIRECT_DSN", runtime_direct_dsn),
                    ("DB_WORKER_DSN", runtime_worker_dsn),
                ],
                &[],
            );
            let owner = if is_root {
                Some((0u32, setjoin_gid.unwrap_or(meta.gid())))
            } else {
                Some((meta.uid(), meta.gid()))
            };
            let mode = meta.mode() & 0o777;
            let safe_mode = if mode == 0o600 || mode == 0o640 {
                mode
            } else {
                0o640
            };
            atomic_write_file(&path, updated.as_bytes(), safe_mode, owner)?;
            written.push(path.display().to_string());
        }
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "setjoin-545-mailctl-{tag}-{}",
            random_hex_24().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    #[test]
    fn deploy004_rejects_symlinks_bad_modes_and_partial_split() {
        let dir = temp_dir("deploy004");
        // 1. Symlink config.env rejected
        let victim = dir.join("victim");
        std::fs::write(&victim, "nope\n").unwrap();
        symlink(&victim, dir.join("config.env")).unwrap();
        let err = validate_deploy004_namespace(&dir).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        std::fs::remove_file(dir.join("config.env")).unwrap();

        // 2. Bad mode on db-credentials.d rejected
        let cred_dir = dir.join("db-credentials.d");
        std::fs::create_dir(&cred_dir).unwrap();
        std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = validate_deploy004_namespace(&dir).unwrap_err();
        assert!(err.contains("0750"), "{err}");
        std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o750)).unwrap();

        // 3. Bad mode on db-credentials.env rejected
        let cred_file = cred_dir.join("db-credentials.env");
        std::fs::write(&cred_file, "DB_OWNER_DSN=postgres://mail@127.0.0.1/db\n").unwrap();
        std::fs::set_permissions(&cred_file, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = validate_deploy004_namespace(&dir).unwrap_err();
        assert!(err.contains("0600"), "{err}");
        std::fs::set_permissions(&cred_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        // 4. Partial split rejected
        std::fs::write(
            dir.join("config.env"),
            "DB_DSN=postgres://mail@127.0.0.1/db\nDB_WORKER_DSN=postgres://w@127.0.0.1/db\n",
        )
        .unwrap();
        let err = validate_deploy004_namespace(&dir).unwrap_err();
        assert!(err.contains("partial privileged-DSN split"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_split_dsn_files_atomically_splits_backs_up_and_syncs_derived_envs() {
        let dir = temp_dir("split-sync");
        let cfg = dir.join("config.env");
        std::fs::write(
            &cfg,
            "HOSTNAME=mail.example.test\nDB_DSN=postgres://mail:old@127.0.0.1:5432/mail\nDB_WORKER_DSN=postgres://mail:old@127.0.0.1:5432/mail\nJWT_SECRET=keep-me\n",
        )
        .unwrap();
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
        let auth_env = dir.join("auth.env");
        std::fs::write(&auth_env, "LISTEN_ADDR=127.0.0.1:8443\nDB_WORKER_DSN=old\n").unwrap();
        std::fs::set_permissions(&auth_env, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fed_env = dir.join("federation.env");
        std::fs::write(
            &fed_env,
            "DB_DSN=old\nDB_DIRECT_DSN=old\nDB_WORKER_DSN=old\nLIVEKIT_URL=ws://127.0.0.1:7880\n",
        )
        .unwrap();
        std::fs::set_permissions(&fed_env, std::fs::Permissions::from_mode(0o640)).unwrap();
        let smtp_env = dir.join("smtp.env");
        std::fs::write(&smtp_env, "DB_DSN=old\nDB_WORKER_DSN=old\n").unwrap();
        std::fs::set_permissions(&smtp_env, std::fs::Permissions::from_mode(0o640)).unwrap();

        let written = write_split_dsn_files(
            &dir,
            "postgres://setjoin_app:app_pw@127.0.0.1:6432/mail",
            "postgres://setjoin_app:app_pw@127.0.0.1:5432/mail",
            "postgres://setjoin_worker:worker_pw@127.0.0.1:6432/mail",
            "postgres://setjoin_owner:owner_pw@127.0.0.1:6432/mail",
            "postgres://setjoin_owner:owner_pw@127.0.0.1:5432/mail",
        )
        .unwrap();
        assert!(written.len() >= 6, "{written:?}");

        // config.env is 0600, has app DSNs, no privileged keys, keeps JWT_SECRET.
        let cfg_text = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(std::fs::metadata(&cfg).unwrap().mode() & 0o777, 0o600);
        assert!(cfg_text.contains("DB_DSN=postgres://setjoin_app:app_pw@127.0.0.1:6432/mail"));
        assert!(
            cfg_text.contains("DB_DIRECT_DSN=postgres://setjoin_app:app_pw@127.0.0.1:5432/mail")
        );
        assert!(cfg_text.contains("JWT_SECRET=keep-me"));
        assert!(!cfg_text.contains("DB_WORKER_DSN="));
        assert!(!cfg_text.contains("DB_OWNER_DSN="));

        // db-credentials.env is 0600 inside 0750 db-credentials.d with all 3 privileged tiers.
        let cred_dir = dir.join("db-credentials.d");
        let cred_file = cred_dir.join("db-credentials.env");
        assert_eq!(std::fs::metadata(&cred_dir).unwrap().mode() & 0o777, 0o750);
        assert_eq!(std::fs::metadata(&cred_file).unwrap().mode() & 0o777, 0o600);
        let cred_text = std::fs::read_to_string(&cred_file).unwrap();
        assert!(cred_text
            .contains("DB_WORKER_DSN=postgres://setjoin_worker:worker_pw@127.0.0.1:6432/mail"));
        assert!(cred_text
            .contains("DB_OWNER_DSN=postgres://setjoin_owner:owner_pw@127.0.0.1:6432/mail"));
        assert!(cred_text
            .contains("DB_DIRECT_OWNER_DSN=postgres://setjoin_owner:owner_pw@127.0.0.1:5432/mail"));

        // Backup exists in db-credentials.d at 0600.
        let backups: Vec<_> = std::fs::read_dir(&cred_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("config.env.pre-provision.")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].metadata().unwrap().mode() & 0o777, 0o600);

        // Derived env files synced atomically with modes preserved.
        let auth_text = std::fs::read_to_string(&auth_env).unwrap();
        assert_eq!(std::fs::metadata(&auth_env).unwrap().mode() & 0o777, 0o600);
        assert!(auth_text.contains("LISTEN_ADDR=127.0.0.1:8443"));
        assert!(auth_text
            .contains("DB_WORKER_DSN=postgres://setjoin_worker:worker_pw@127.0.0.1:6432/mail"));

        let fed_text = std::fs::read_to_string(&fed_env).unwrap();
        assert_eq!(std::fs::metadata(&fed_env).unwrap().mode() & 0o777, 0o640);
        assert!(fed_text.contains("DB_DSN=postgres://setjoin_app:app_pw@127.0.0.1:6432/mail"));
        assert!(fed_text
            .contains("DB_WORKER_DSN=postgres://setjoin_worker:worker_pw@127.0.0.1:6432/mail"));
        assert!(fed_text.contains("LIVEKIT_URL=ws://127.0.0.1:7880"));

        let smtp_text = std::fs::read_to_string(&smtp_env).unwrap();
        assert_eq!(std::fs::metadata(&smtp_env).unwrap().mode() & 0o777, 0o640);
        assert!(smtp_text.contains("DB_DSN=postgres://setjoin_app:app_pw@127.0.0.1:6432/mail"));
        assert!(smtp_text
            .contains("DB_WORKER_DSN=postgres://setjoin_worker:worker_pw@127.0.0.1:6432/mail"));

        // Re-validating passes DEPLOY-004 cleanly.
        validate_deploy004_namespace(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_passwords_refuses_when_updater_dsn_files_exist() {
        let dir = temp_dir("updater-guard");
        check_updater_sync_guard(&dir).unwrap();
        std::fs::write(
            dir.join("app-worker-dsn"),
            "postgres://setjoin_worker@127.0.0.1/db\n",
        )
        .unwrap();
        let err = check_updater_sync_guard(&dir).unwrap_err();
        assert!(err.contains("out of sync"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_passwords_without_write_dsns_is_refused() {
        let err = validate_provision_flags(false, true).unwrap_err();
        assert!(
            err.contains("--rotate-passwords requires --write-dsns"),
            "{err}"
        );
        validate_provision_flags(true, true).unwrap();
        validate_provision_flags(true, false).unwrap();
        validate_provision_flags(false, false).unwrap();
    }

    #[test]
    fn read_env_map_nofollow_strips_matching_systemd_quotes() {
        let dir = temp_dir("env-quotes");
        let path = dir.join("config.env");
        std::fs::write(
            &path,
            "DB_DSN=\"postgres://setjoin_app:pw1@127.0.0.1:5432/mail\"\n\
             DB_WORKER_DSN='postgres://setjoin_worker:pw2@127.0.0.1:5432/mail'\n\
             PLAIN=value\n\
             MISMATCH=\"abc'\n",
        )
        .unwrap();
        let map = read_env_map_nofollow(&path).unwrap();
        assert_eq!(
            map.get("DB_DSN").map(String::as_str),
            Some("postgres://setjoin_app:pw1@127.0.0.1:5432/mail")
        );
        assert_eq!(
            map.get("DB_WORKER_DSN").map(String::as_str),
            Some("postgres://setjoin_worker:pw2@127.0.0.1:5432/mail")
        );
        assert_eq!(map.get("PLAIN").map(String::as_str), Some("value"));
        assert_eq!(map.get("MISMATCH").map(String::as_str), Some("\"abc'"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
