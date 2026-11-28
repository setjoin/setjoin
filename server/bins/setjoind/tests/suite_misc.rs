//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;

#[path = "acme_deprecation.rs"]
mod acme_deprecation;
#[path = "cli_and_guards.rs"]
mod cli_and_guards;
#[path = "colocated_all.rs"]
mod colocated_all;
#[path = "edge_contract_conformance.rs"]
mod edge_contract_conformance;
#[path = "graceful_shutdown.rs"]
mod graceful_shutdown;
#[path = "listen_hub_multiplex.rs"]
mod listen_hub_multiplex;
#[path = "schema_refusal.rs"]
mod schema_refusal;
#[path = "shims.rs"]
mod shims;
#[path = "socket_activation.rs"]
mod socket_activation;
#[path = "split_remote_auth.rs"]
mod split_remote_auth;
#[path = "workers_standalone.rs"]
mod workers_standalone;
