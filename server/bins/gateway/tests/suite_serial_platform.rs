//! Consolidated integration test suite `suite_serial_platform` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod ad_oracle;
#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "common/fake_microsoft.rs"]
pub mod fake_microsoft;
#[allow(dead_code)]
pub mod migration_runner_oracle;
#[allow(dead_code, unused_imports)]
pub mod platform_oracle;
#[allow(dead_code)]
pub mod platform_webhooks_oracle;

#[path = "ad_runtime.rs"]
mod ad_runtime;
#[path = "authz_deny_final.rs"]
mod authz_deny_final;
#[path = "migration_providers.rs"]
mod migration_providers;
#[path = "migration_runner.rs"]
mod migration_runner;
#[path = "platform_airgap.rs"]
mod platform_airgap;
#[path = "platform_alerts.rs"]
mod platform_alerts;
#[path = "platform_apps.rs"]
mod platform_apps;
#[path = "platform_auth_admin.rs"]
mod platform_auth_admin;
#[path = "platform_branding.rs"]
mod platform_branding;
#[path = "platform_config.rs"]
mod platform_config;
#[path = "platform_deploy.rs"]
mod platform_deploy;
#[path = "platform_dns.rs"]
mod platform_dns;
#[path = "platform_domains.rs"]
mod platform_domains;
#[path = "platform_features.rs"]
mod platform_features;
#[path = "platform_federation.rs"]
mod platform_federation;
#[path = "platform_jobs_storage.rs"]
mod platform_jobs_storage;
#[path = "platform_monitor.rs"]
mod platform_monitor;
#[path = "platform_qualification.rs"]
mod platform_qualification;
#[path = "platform_recovery_admin.rs"]
mod platform_recovery_admin;
#[path = "platform_retired.rs"]
mod platform_retired;
#[path = "platform_setup.rs"]
mod platform_setup;
#[path = "platform_storage_runtime.rs"]
mod platform_storage_runtime;
#[path = "platform_sysconf.rs"]
mod platform_sysconf;
#[path = "platform_system.rs"]
mod platform_system;
#[path = "platform_terms.rs"]
mod platform_terms;
#[path = "platform_updates.rs"]
mod platform_updates;
#[path = "platform_upgrades.rs"]
mod platform_upgrades;
#[path = "platform_webhooks.rs"]
mod platform_webhooks;
#[path = "secfix11.rs"]
mod secfix11;
#[path = "secfix9.rs"]
mod secfix9;
#[path = "static2_discovery.rs"]
mod static2_discovery;
