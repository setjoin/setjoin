//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[path = "bounds.rs"]
mod bounds;
#[path = "capability_tx.rs"]
mod capability_tx;
#[path = "db_scope.rs"]
mod db_scope;
#[path = "listen_hub.rs"]
mod listen_hub;
#[path = "rls_full_matrix.rs"]
mod rls_full_matrix;
#[path = "rls_preflight.rs"]
mod rls_preflight;
#[path = "workers.rs"]
mod workers;
