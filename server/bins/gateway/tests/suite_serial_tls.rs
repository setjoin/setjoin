//! Consolidated integration test suite `suite_serial_tls` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;

#[path = "tls_front.rs"]
mod tls_front;
#[path = "tls_recorded.rs"]
mod tls_recorded;
