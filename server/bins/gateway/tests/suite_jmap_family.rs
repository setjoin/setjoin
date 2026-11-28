//! Consolidated integration test suite `suite_jmap_family` (preserves exact submodule test coverage).

#[allow(dead_code, unused_imports)]
pub mod common;
#[allow(dead_code, unused_imports)]
pub mod jmap_family_oracle;

#[path = "jmap_family_369.rs"]
mod jmap_family_369;
#[path = "jmap_family_370.rs"]
mod jmap_family_370;
#[path = "jmap_family_371.rs"]
mod jmap_family_371;
#[path = "jmap_family_372.rs"]
mod jmap_family_372;
#[path = "jmap_family_373.rs"]
mod jmap_family_373;
#[path = "jmap_family_374.rs"]
mod jmap_family_374;
#[path = "jmap_family_375.rs"]
mod jmap_family_375;
#[path = "jmap_family_376.rs"]
mod jmap_family_376;
#[path = "jmap_family_377.rs"]
mod jmap_family_377;
#[path = "jmap_push_recorded.rs"]
mod jmap_push_recorded;
#[path = "jmap_sse_recorded.rs"]
mod jmap_sse_recorded;
