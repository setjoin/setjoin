//! Consolidated integration test suite `suite_serial_auth_3` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "common/revoke.rs"]
pub mod revoke;
#[allow(dead_code)]
#[path = "common/webauthn_commit.rs"]
pub mod wire;

#[path = "rp_faults.rs"]
mod rp_faults;
#[path = "rp_oidclax.rs"]
mod rp_oidclax;
#[path = "rp_oracle.rs"]
mod rp_oracle;
#[path = "rp_secfix13.rs"]
mod rp_secfix13;
#[path = "rp_secfix8.rs"]
mod rp_secfix8;
#[path = "rp_swap.rs"]
mod rp_swap;
