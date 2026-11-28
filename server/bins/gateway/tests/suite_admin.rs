//! Consolidated integration test suite `suite_admin` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod admin_access_reviews_oracle;
#[allow(dead_code)]
pub mod admin_identity_oracle;
#[allow(dead_code)]
pub mod admin_identity_roles_oracle;
#[allow(dead_code)]
pub mod admin_identity_v2_upgrade_oracle;
#[allow(dead_code)]
pub mod admin_org_policies_oracle;
#[allow(dead_code)]
pub mod admin_scope_sets_oracle;
#[allow(dead_code)]
pub mod admin_sod_oracle;
#[allow(dead_code)]
pub mod admin_users_lifecycle_oracle;
#[allow(dead_code)]
pub mod ca_policies_oracle;
#[allow(dead_code)]
pub mod ca_remaining_oracle;
#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
pub mod devices_oracle;
#[allow(dead_code)]
pub mod dirsync_oracle;
#[allow(dead_code)]
#[path = "common/fake_imap.rs"]
pub mod fake_imap;
#[allow(dead_code)]
pub mod guests_oracle;
#[allow(dead_code)]
pub mod identity_self_service_oracle;
#[allow(dead_code)]
pub mod mam_oracle;
#[allow(dead_code)]
pub mod scim_oracle;

#[path = "admin_access_reviews.rs"]
mod admin_access_reviews;
#[path = "admin_identity.rs"]
mod admin_identity;
#[path = "admin_identity_roles.rs"]
mod admin_identity_roles;
#[path = "admin_identity_v2_upgrade.rs"]
mod admin_identity_v2_upgrade;
#[path = "admin_org_policies.rs"]
mod admin_org_policies;
#[path = "admin_scope_sets.rs"]
mod admin_scope_sets;
#[path = "admin_sod.rs"]
mod admin_sod;
#[path = "admin_users_lifecycle.rs"]
mod admin_users_lifecycle;
#[path = "approvals.rs"]
mod approvals;
#[path = "ca_policies.rs"]
mod ca_policies;
#[path = "ca_remaining.rs"]
mod ca_remaining;
#[path = "devices.rs"]
mod devices;
#[path = "directory_sync.rs"]
mod directory_sync;
#[path = "guests.rs"]
mod guests;
#[path = "identity_self_service.rs"]
mod identity_self_service;
#[path = "mam.rs"]
mod mam;
#[path = "scim.rs"]
mod scim;
