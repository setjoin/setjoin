//! Release N `setjoin-auth` compatibility shim (#544).
//!
//! Execs sibling `setjoind --subsystems=auth` in-place while preserving PID,
//! inherited systemd socket-activation FDs, and `--version` compatibility.

#[path = "../shim_exec.rs"]
mod shim_exec;

use std::process::ExitCode;

fn main() -> ExitCode {
    shim_exec::run_shim("setjoin-auth", "auth", shim_exec::SUB_AUTH)
}
