//! Consolidated integration test suite `suite_static_misc` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;

#[path = "catchall_recorded.rs"]
mod catchall_recorded;
#[path = "gateway_config_runtime.rs"]
mod gateway_config_runtime;
#[path = "static2_health.rs"]
mod static2_health;
#[path = "static_recorded.rs"]
mod static_recorded;
