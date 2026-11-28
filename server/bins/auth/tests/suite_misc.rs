//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[allow(dead_code)]
#[path = "../../gateway/tests/common/commit.rs"]
pub mod commit;
#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "common/revoke.rs"]
pub mod revoke;
#[allow(dead_code)]
#[path = "../../../crates/domains/identity/tests/saml_acs/support.rs"]
pub mod saml_support;
#[allow(dead_code)]
#[path = "common/webauthn_commit.rs"]
pub mod webauthn_commit;

#[path = "ca_351.rs"]
mod ca_351;
#[path = "commit_faults.rs"]
mod commit_faults;
#[path = "delete_gate.rs"]
mod delete_gate;
#[path = "device_faults.rs"]
mod device_faults;
#[path = "fail_closed.rs"]
mod fail_closed;
#[path = "guest_scope.rs"]
mod guest_scope;
#[path = "handoff.rs"]
mod handoff;
#[path = "http_recorded.rs"]
mod http_recorded;
#[path = "identity_fail_closed_454.rs"]
mod identity_fail_closed_454;
#[path = "mfa_faults.rs"]
mod mfa_faults;
#[path = "oidc_config.rs"]
mod oidc_config;
#[path = "oidc_faults.rs"]
mod oidc_faults;
#[path = "oidc_secfix10.rs"]
mod oidc_secfix10;
#[path = "oidc_secfix7.rs"]
mod oidc_secfix7;
#[path = "oidc_swap.rs"]
mod oidc_swap;
#[path = "push_delivery.rs"]
mod push_delivery;
#[path = "reload_process.rs"]
mod reload_process;
#[path = "rp_secrets.rs"]
mod rp_secrets;
#[path = "saml_faults.rs"]
mod saml_faults;
#[path = "saml_interop.rs"]
mod saml_interop;
#[path = "saml_legacy.rs"]
mod saml_legacy;
#[path = "saml_worker.rs"]
mod saml_worker;
#[path = "secfix3.rs"]
mod secfix3;
#[path = "startup.rs"]
mod startup;
#[path = "token_faults.rs"]
mod token_faults;
#[path = "token_recorded.rs"]
mod token_recorded;
#[path = "webauthn_faults.rs"]
mod webauthn_faults;
