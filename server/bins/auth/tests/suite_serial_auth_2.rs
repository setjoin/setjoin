//! Consolidated integration test suite `suite_serial_auth_2` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "common/session_commit.rs"]
pub mod wire;

#[path = "csrf.rs"]
mod csrf;
#[path = "session_faults.rs"]
mod session_faults;
