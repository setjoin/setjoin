//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[path = "push_formats.rs"]
mod push_formats;
#[path = "saml_acs_c14n.rs"]
mod saml_acs_c14n;
#[path = "totp.rs"]
mod totp;
#[path = "webauthn.rs"]
mod webauthn;
