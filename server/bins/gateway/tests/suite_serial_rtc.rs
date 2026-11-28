//! Consolidated integration test suite `suite_serial_rtc` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;

#[path = "rtc_dispatch.rs"]
mod rtc_dispatch;
#[path = "rtc_recorded.rs"]
mod rtc_recorded;
