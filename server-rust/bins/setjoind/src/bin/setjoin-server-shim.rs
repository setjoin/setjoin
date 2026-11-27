//! Release N `setjoin-server` compatibility shim (#544).
//!
//! Execs sibling `setjoind --subsystems=http,protocols,workers` in-place while
//! preserving PID, inherited systemd socket-activation FDs (`3..12`), and
//! `--version` compatibility for `scripts/smoke-rust-floor.sh`.

#[path = "../shim_exec.rs"]
mod shim_exec;

use std::process::ExitCode;

fn main() -> ExitCode {
    shim_exec::run_shim(
        "setjoin-server",
        "http,protocols,workers",
        shim_exec::SUB_HTTP | shim_exec::SUB_PROTOCOLS | shim_exec::SUB_WORKERS,
    )
}
