//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;

#[path = "interop.rs"]
mod interop;
#[path = "pem_hot_reload.rs"]
mod pem_hot_reload;
#[path = "reaper.rs"]
mod reaper;
#[path = "replay.rs"]
mod replay;
#[path = "runtime.rs"]
mod runtime;
#[path = "stream.rs"]
mod stream;
