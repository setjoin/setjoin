//! Consolidated integration test suite `suite_settings` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
pub mod settings_oracle;

#[path = "settings_a.rs"]
mod settings_a;
#[path = "settings_b.rs"]
mod settings_b;
#[path = "settings_c.rs"]
mod settings_c;
#[path = "settings_profile.rs"]
mod settings_profile;
