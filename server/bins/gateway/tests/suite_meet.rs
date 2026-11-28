//! Consolidated integration test suite `suite_meet` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "common/meet_peripherals.rs"]
pub mod peripherals;

#[path = "meet_a_recorded.rs"]
mod meet_a_recorded;
#[path = "meet_b_recorded.rs"]
mod meet_b_recorded;
#[path = "meet_c_recorded.rs"]
mod meet_c_recorded;
#[path = "meet_recorded.rs"]
mod meet_recorded;
