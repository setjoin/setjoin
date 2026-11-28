//! Consolidated integration test suite `suite_auth_catalog` (preserves exact submodule test coverage).

#[allow(dead_code)]
#[path = "common/webauthn_commit.rs"]
pub mod commit;
#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "common/revoke.rs"]
pub mod revoke;

#[path = "device_oracle.rs"]
mod device_oracle;
#[path = "guest_invite_oracle.rs"]
mod guest_invite_oracle;
#[path = "mfa_oracle.rs"]
mod mfa_oracle;
#[path = "oidc_oracle.rs"]
mod oidc_oracle;
#[path = "oracle.rs"]
mod oracle;
#[path = "push_oracle.rs"]
mod push_oracle;
#[path = "saml_oracle.rs"]
mod saml_oracle;
#[path = "webauthn_oracle.rs"]
mod webauthn_oracle;
