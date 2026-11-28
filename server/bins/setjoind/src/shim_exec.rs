//! Shared `std`-only exec helper for Release N compatibility shims (#544).
//!
//! Deliberately avoids linking `setjoind` or any non-`std` runtime crate (uses
//! only `std`, plus `libc` on Linux for `O_NOFOLLOW | O_CLOEXEC` + `fstat` +
//! `execveat(AT_EMPTY_PATH)` / `fexecve`).

use std::ffi::OsString;
use std::process::ExitCode;

pub const SUB_HTTP: u8 = 1 << 0;
pub const SUB_AUTH: u8 = 1 << 1;
pub const SUB_PROTOCOLS: u8 = 1 << 2;
pub const SUB_WORKERS: u8 = 1 << 3;
pub const SUB_ALL: u8 = SUB_HTTP | SUB_AUTH | SUB_PROTOCOLS | SUB_WORKERS;

/// Exit code for invalid or conflicting CLI/environment arguments.
const EXIT_USAGE: u8 = 2;

/// Immutable ELF marker allowing `upgrade.sh` to detect a Release N shim
/// without executing it, refusing shim upgrades that lack a companion `setjoind`.
#[used]
static SHIM_MARKER: &[u8] = b"SETJOIND_SHIM_V1\0";

fn parse_subsystems_mask(raw: &str) -> Result<u8, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty subsystem list".into());
    }
    let mut mask: u8 = 0;
    let mut saw_all = false;
    let mut count = 0usize;
    for part in trimmed.split(',') {
        let token = part.trim();
        if token.is_empty() {
            return Err(format!("empty entry in subsystem list {raw:?}"));
        }
        count += 1;
        match token {
            "all" => {
                if saw_all {
                    return Err("duplicate subsystem \"all\"".into());
                }
                saw_all = true;
                mask = SUB_ALL;
            }
            "http" => {
                if mask & SUB_HTTP != 0 {
                    return Err("duplicate subsystem \"http\"".into());
                }
                mask |= SUB_HTTP;
            }
            "auth" => {
                if mask & SUB_AUTH != 0 {
                    return Err("duplicate subsystem \"auth\"".into());
                }
                mask |= SUB_AUTH;
            }
            "protocols" => {
                if mask & SUB_PROTOCOLS != 0 {
                    return Err("duplicate subsystem \"protocols\"".into());
                }
                mask |= SUB_PROTOCOLS;
            }
            "workers" => {
                if mask & SUB_WORKERS != 0 {
                    return Err("duplicate subsystem \"workers\"".into());
                }
                mask |= SUB_WORKERS;
            }
            other => {
                return Err(format!("unknown subsystem {other:?}"));
            }
        }
    }
    if saw_all && count > 1 {
        return Err("cannot combine \"all\" with individual subsystem names".into());
    }
    if mask == 0 {
        return Err("at least one subsystem must be enabled".into());
    }
    Ok(mask)
}

pub fn run_shim(shim_name: &str, fixed_subsystems: &str, fixed_mask: u8) -> ExitCode {
    let _ = SHIM_MARKER[0];
    let args: Vec<OsString> = std::env::args_os().collect();

    if args.len() == 2 {
        if let Some(arg1) = args[1].to_str() {
            if arg1 == "--version" || arg1 == "-V" {
                println!("{shim_name} {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
        }
    }

    if let Some(raw_env) = std::env::var_os("SETJOIND_SUBSYSTEMS") {
        let Some(env_str) = raw_env.to_str() else {
            eprintln!(
                "{shim_name}: SETJOIND_SUBSYSTEMS is not valid UTF-8 and conflicts with fixed subsystems ({fixed_subsystems})"
            );
            return ExitCode::from(EXIT_USAGE);
        };
        let trimmed = env_str.trim();
        if !trimmed.is_empty() {
            match parse_subsystems_mask(trimmed) {
                Ok(mask) if mask == fixed_mask => {}
                Ok(_) => {
                    eprintln!(
                        "{shim_name}: SETJOIND_SUBSYSTEMS={trimmed:?} conflicts with fixed shim subsystems ({fixed_subsystems})"
                    );
                    return ExitCode::from(EXIT_USAGE);
                }
                Err(err) => {
                    eprintln!("{shim_name}: invalid SETJOIND_SUBSYSTEMS={trimmed:?}: {err}");
                    return ExitCode::from(EXIT_USAGE);
                }
            }
        }
    }

    let mut passthrough: Vec<OsString> = Vec::new();
    let mut saw_subsystems = false;
    let mut iter = args.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        if let Some(s) = arg.to_str() {
            if s == "--subsystems" {
                if saw_subsystems {
                    eprintln!("{shim_name}: duplicate --subsystems flag is not allowed");
                    return ExitCode::from(EXIT_USAGE);
                }
                saw_subsystems = true;
                let Some(val_os) = iter.next() else {
                    eprintln!("{shim_name}: --subsystems requires a value");
                    return ExitCode::from(EXIT_USAGE);
                };
                let Some(val) = val_os.to_str() else {
                    eprintln!("{shim_name}: --subsystems value is not valid UTF-8");
                    return ExitCode::from(EXIT_USAGE);
                };
                match parse_subsystems_mask(val) {
                    Ok(mask) if mask == fixed_mask => continue,
                    Ok(_) => {
                        eprintln!(
                            "{shim_name}: --subsystems={val:?} conflicts with fixed shim subsystems ({fixed_subsystems})"
                        );
                        return ExitCode::from(EXIT_USAGE);
                    }
                    Err(err) => {
                        eprintln!("{shim_name}: invalid --subsystems={val:?}: {err}");
                        return ExitCode::from(EXIT_USAGE);
                    }
                }
            }
            if let Some(val) = s.strip_prefix("--subsystems=") {
                if saw_subsystems {
                    eprintln!("{shim_name}: duplicate --subsystems flag is not allowed");
                    return ExitCode::from(EXIT_USAGE);
                }
                saw_subsystems = true;
                match parse_subsystems_mask(val) {
                    Ok(mask) if mask == fixed_mask => continue,
                    Ok(_) => {
                        eprintln!(
                            "{shim_name}: --subsystems={val:?} conflicts with fixed shim subsystems ({fixed_subsystems})"
                        );
                        return ExitCode::from(EXIT_USAGE);
                    }
                    Err(err) => {
                        eprintln!("{shim_name}: invalid --subsystems={val:?}: {err}");
                        return ExitCode::from(EXIT_USAGE);
                    }
                }
            }
        }
        passthrough.push(arg);
    }

    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("{shim_name}: cannot resolve current executable path: {err}");
            return ExitCode::FAILURE;
        }
    };
    let Some(dir) = exe.parent() else {
        eprintln!(
            "{shim_name}: executable path {} has no parent directory",
            exe.display()
        );
        return ExitCode::FAILURE;
    };
    let target = dir.join("setjoind");

    match exec_sibling(&target, fixed_subsystems, &passthrough) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{shim_name}: failed to exec {}: {err}", target.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn exec_sibling(
    target: &std::path::Path,
    fixed_subsystems: &str,
    passthrough: &[OsString],
) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let c_target = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| "target path contains NUL byte".to_string())?;

    // Open with O_NOFOLLOW | O_CLOEXEC so there is zero TOCTOU window and zero
    // extra non-CLOEXEC FD leaked into inherited socket activation FDs 3..12.
    let raw_fd = unsafe {
        libc::open(
            c_target.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: `raw_fd` was just returned by `open(2)` with `O_CLOEXEC`.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err("sibling setjoind is not a regular file".into());
    }
    if st.st_nlink != 1 {
        return Err(format!(
            "sibling setjoind must have link count 1 (got {})",
            st.st_nlink
        ));
    }
    if (st.st_mode & 0o022) != 0 {
        return Err(format!(
            "sibling setjoind must not be group- or world-writable (mode {:o})",
            st.st_mode & 0o7777
        ));
    }

    let mut argv_storage: Vec<CString> = Vec::with_capacity(2 + passthrough.len());
    argv_storage.push(c_target);
    argv_storage.push(
        CString::new(format!("--subsystems={fixed_subsystems}"))
            .map_err(|_| "subsystems argument contains NUL byte".to_string())?,
    );
    for arg in passthrough {
        argv_storage.push(
            CString::new(arg.as_bytes())
                .map_err(|_| "passthrough argument contains NUL byte".to_string())?,
        );
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_storage.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let mut envp_storage: Vec<CString> = Vec::new();
    for (k, v) in std::env::vars_os() {
        if k == "SETJOIND_SUBSYSTEMS" {
            continue;
        }
        let mut entry = Vec::with_capacity(k.len() + 1 + v.len());
        entry.extend_from_slice(k.as_bytes());
        entry.push(b'=');
        entry.extend_from_slice(v.as_bytes());
        if let Ok(c_entry) = CString::new(entry) {
            envp_storage.push(c_entry);
        }
    }
    envp_storage.push(
        CString::new(format!("SETJOIND_SUBSYSTEMS={fixed_subsystems}"))
            .map_err(|_| "SETJOIND_SUBSYSTEMS contains NUL byte".to_string())?,
    );
    let mut envp_ptrs: Vec<*const libc::c_char> = envp_storage.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let empty = c"";
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd.as_raw_fd() as libc::c_long,
            empty.as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_long,
        );
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOSYS) {
        unsafe {
            libc::fexecve(fd.as_raw_fd(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
        }
        return Err(std::io::Error::last_os_error().to_string());
    }
    Err(err.to_string())
}

#[cfg(not(target_os = "linux"))]
fn exec_sibling(
    target: &std::path::Path,
    fixed_subsystems: &str,
    passthrough: &[OsString],
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;

    let meta = std::fs::symlink_metadata(target).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("sibling setjoind is not a regular file (symlinks are refused)".into());
    }
    if meta.nlink() != 1 {
        return Err(format!(
            "sibling setjoind must have link count 1 (got {})",
            meta.nlink()
        ));
    }
    if (meta.mode() & 0o022) != 0 {
        return Err(format!(
            "sibling setjoind must not be group- or world-writable (mode {:o})",
            meta.mode() & 0o7777
        ));
    }

    let err = std::process::Command::new(target)
        .arg(format!("--subsystems={fixed_subsystems}"))
        .args(passthrough)
        .env("SETJOIND_SUBSYSTEMS", fixed_subsystems)
        .exec();
    Err(err.to_string())
}
