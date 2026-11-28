//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[path = "admit_db.rs"]
mod admit_db;
#[path = "basic_password.rs"]
mod basic_password;
#[path = "chain_worker.rs"]
mod chain_worker;
#[path = "device_credential.rs"]
mod device_credential;
#[path = "legacy_jwt.rs"]
mod legacy_jwt;
#[path = "password_formats.rs"]
mod password_formats;
#[path = "policy_gate_db.rs"]
mod policy_gate_db;
#[path = "push_legacy.rs"]
mod push_legacy;
#[path = "runtime_gates.rs"]
mod runtime_gates;
#[path = "signing_keys.rs"]
mod signing_keys;
