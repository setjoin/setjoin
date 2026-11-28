//! Consolidated integration test suite `suite_recovery` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;

#[path = "recovery_abort.rs"]
mod recovery_abort;
#[path = "recovery_begin.rs"]
mod recovery_begin;
#[path = "recovery_chunk.rs"]
mod recovery_chunk;
#[path = "recovery_commit.rs"]
mod recovery_commit;
#[path = "recovery_finalize.rs"]
mod recovery_finalize;
#[path = "recovery_fork.rs"]
mod recovery_fork;
#[path = "recovery_incidents.rs"]
mod recovery_incidents;
