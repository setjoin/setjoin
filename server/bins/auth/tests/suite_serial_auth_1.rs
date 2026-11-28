//! Consolidated integration test suite `suite_serial_auth_1` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "../../../crates/domains/identity/tests/saml_acs/support.rs"]
pub mod saml_support;

#[path = "config.rs"]
mod config;
#[path = "device_proof_oracle.rs"]
mod device_proof_oracle;
#[path = "threat_oracle.rs"]
mod threat_oracle;
#[path = "token_oracle.rs"]
mod token_oracle;
