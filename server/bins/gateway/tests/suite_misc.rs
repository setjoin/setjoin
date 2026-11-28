//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "common/fake_imap.rs"]
pub mod fake_imap;
#[allow(dead_code)]
pub mod jmap_family_oracle;
#[allow(dead_code)]
#[path = "common/meet_peripherals.rs"]
pub mod meet_peripherals;
#[allow(dead_code)]
#[path = "common/office_fixture.rs"]
pub mod office_fixture;
#[allow(dead_code)]
#[path = "../../../crates/protocols/smtp/tests/support/outbound.rs"]
pub mod outbound_oracle;
#[allow(dead_code)]
#[path = "common/drive_s3.rs"]
pub mod storage_wire;

#[path = "ad_startup.rs"]
mod ad_startup;
#[path = "admin_identity_startup.rs"]
mod admin_identity_startup;
#[path = "admin_job_workers_startup.rs"]
mod admin_job_workers_startup;
#[path = "admin_users_lifecycle_delivery.rs"]
mod admin_users_lifecycle_delivery;
#[path = "approvals_startup.rs"]
mod approvals_startup;
#[path = "authz_defer_recorded.rs"]
mod authz_defer_recorded;
#[path = "blob_cleanup_startup.rs"]
mod blob_cleanup_startup;
#[path = "blob_mark_and_sweep_gc.rs"]
mod blob_mark_and_sweep_gc;
#[path = "booking_expiry_startup.rs"]
mod booking_expiry_startup;
#[path = "boot.rs"]
mod boot;
#[path = "calendar_rrule.rs"]
mod calendar_rrule;
#[path = "catchall_startup.rs"]
mod catchall_startup;
#[path = "cert_monitor.rs"]
mod cert_monitor;
#[path = "chat_changes_retention.rs"]
mod chat_changes_retention;
#[path = "chat_deferred_recorded.rs"]
mod chat_deferred_recorded;
#[path = "chat_worker_recorded.rs"]
mod chat_worker_recorded;
#[path = "cron_catalog.rs"]
mod cron_catalog;
#[path = "cron_handover.rs"]
mod cron_handover;
#[path = "dav_basic_auth.rs"]
mod dav_basic_auth;
#[path = "dav_negotiate_auth.rs"]
mod dav_negotiate_auth;
#[path = "delete_gate.rs"]
mod delete_gate;
#[path = "devices_startup.rs"]
mod devices_startup;
#[path = "directory_sync_startup.rs"]
mod directory_sync_startup;
#[path = "dmarc_report_startup.rs"]
mod dmarc_report_startup;
#[path = "drive_b_dispatch.rs"]
mod drive_b_dispatch;
#[path = "drive_b_stream_failure.rs"]
mod drive_b_stream_failure;
#[path = "drive_c_dispatch.rs"]
mod drive_c_dispatch;
#[path = "drive_core_dispatch.rs"]
mod drive_core_dispatch;
#[path = "drive_native_startup.rs"]
mod drive_native_startup;
#[path = "drive_watch.rs"]
mod drive_watch;
#[path = "drive_watch_startup.rs"]
mod drive_watch_startup;
#[path = "drive_workers_startup.rs"]
mod drive_workers_startup;
#[path = "email_get_db.rs"]
mod email_get_db;
#[path = "exchange_startup.rs"]
mod exchange_startup;
#[path = "exchange_worker_startup.rs"]
mod exchange_worker_startup;
#[path = "f15_dispatch.rs"]
mod f15_dispatch;
#[path = "f16_dispatch.rs"]
mod f16_dispatch;
#[path = "federation_activation.rs"]
mod federation_activation;
#[path = "gateway_config.rs"]
mod gateway_config;
#[path = "guests_startup.rs"]
mod guests_startup;
#[path = "http_lifecycle.rs"]
mod http_lifecycle;
#[path = "identity_source_startup.rs"]
mod identity_source_startup;
#[path = "imap_activation.rs"]
mod imap_activation;
#[path = "inventory_guard.rs"]
mod inventory_guard;
#[path = "jmap_batch_delegate.rs"]
mod jmap_batch_delegate;
#[path = "jmap_db.rs"]
mod jmap_db;
#[path = "jmap_family_oracle_selftest.rs"]
mod jmap_family_oracle_selftest;
#[path = "jmap_push_profiles_recorded.rs"]
mod jmap_push_profiles_recorded;
#[path = "ldap_startup.rs"]
mod ldap_startup;
#[path = "link_protect_config_file.rs"]
mod link_protect_config_file;
#[path = "mail_workers_startup.rs"]
mod mail_workers_startup;
#[path = "mailbox_io_startup.rs"]
mod mailbox_io_startup;
#[path = "mailboxes_startup.rs"]
mod mailboxes_startup;
#[path = "mdm_notify_recorded.rs"]
mod mdm_notify_recorded;
#[path = "meet_worker_recorded.rs"]
mod meet_worker_recorded;
#[path = "meet_worker_startup.rs"]
mod meet_worker_startup;
#[path = "migration_runner_connector.rs"]
mod migration_runner_connector;
#[path = "migration_runner_startup.rs"]
mod migration_runner_startup;
#[path = "migration_startup.rs"]
mod migration_startup;
#[path = "notify_drain_startup.rs"]
mod notify_drain_startup;
#[path = "policy_store.rs"]
mod policy_store;
#[path = "problem_bytes.rs"]
mod problem_bytes;
#[path = "proxy.rs"]
mod proxy;
#[path = "push_drain_startup.rs"]
mod push_drain_startup;
#[path = "recovery_dispatch.rs"]
mod recovery_dispatch;
#[path = "recovery_s3.rs"]
mod recovery_s3;
#[path = "recovery_worker.rs"]
mod recovery_worker;
#[path = "rtc_unconfigured_recorded.rs"]
mod rtc_unconfigured_recorded;
#[path = "runtime_access_failures.rs"]
mod runtime_access_failures;
#[path = "scim_startup.rs"]
mod scim_startup;
#[path = "search_worker_db.rs"]
mod search_worker_db;
#[path = "secevents_startup.rs"]
mod secevents_startup;
#[path = "secfix13.rs"]
mod secfix13;
#[path = "secfix3_csrf.rs"]
mod secfix3_csrf;
#[path = "secfix3_policy.rs"]
mod secfix3_policy;
#[path = "secfix3_rules.rs"]
mod secfix3_rules;
#[path = "secfix4.rs"]
mod secfix4;
#[path = "secfix5.rs"]
mod secfix5;
#[path = "secfix6.rs"]
mod secfix6;
#[path = "secfix8.rs"]
mod secfix8;
#[path = "set_seen_db.rs"]
mod set_seen_db;
#[path = "smime_trust_reconnect.rs"]
mod smime_trust_reconnect;
#[path = "smime_trust_startup.rs"]
mod smime_trust_startup;
#[path = "smtp_activation.rs"]
mod smtp_activation;
#[path = "smtp_inbound_dashboard.rs"]
mod smtp_inbound_dashboard;
#[path = "smtp_inbound_trust.rs"]
mod smtp_inbound_trust;
#[path = "smtp_outbound.rs"]
mod smtp_outbound;
#[path = "smtp_transport.rs"]
mod smtp_transport;
#[path = "spam_trainer_startup.rs"]
mod spam_trainer_startup;
#[path = "stalled_db.rs"]
mod stalled_db;
#[path = "startup.rs"]
mod startup;
#[path = "static_native.rs"]
mod static_native;
#[path = "subscription_sync_startup.rs"]
mod subscription_sync_startup;
#[path = "subtree_dispatch.rs"]
mod subtree_dispatch;
#[path = "sync_wakeup_hub.rs"]
mod sync_wakeup_hub;
#[path = "tls_rpt_startup.rs"]
mod tls_rpt_startup;
#[path = "tls_startup.rs"]
mod tls_startup;
#[path = "unmatched_recorded.rs"]
mod unmatched_recorded;
#[path = "user_risk_startup.rs"]
mod user_risk_startup;
#[path = "webhook_dispatch.rs"]
mod webhook_dispatch;
#[path = "webhook_workers_startup.rs"]
mod webhook_workers_startup;
#[path = "worker_supervisor.rs"]
mod worker_supervisor;
#[path = "workers.rs"]
mod workers;
