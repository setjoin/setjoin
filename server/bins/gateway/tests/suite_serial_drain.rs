//! Consolidated integration test suite `suite_serial_drain` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
pub mod drain_oracle;
#[allow(dead_code)]
#[path = "drive_workers_oracle/fake_s3.rs"]
pub mod fake_s3;
#[allow(dead_code)]
#[path = "common/meet_peripherals.rs"]
pub mod meet_peripherals;
#[allow(dead_code)]
#[path = "drain_oracle/peers.rs"]
pub mod peers;

#[path = "blob_cleanup_recorded.rs"]
mod blob_cleanup_recorded;
#[path = "blob_retention_recorded.rs"]
mod blob_retention_recorded;
#[path = "dmarc_report_recorded.rs"]
mod dmarc_report_recorded;
#[path = "drive_workers_recorded.rs"]
mod drive_workers_recorded;
#[path = "health_alerts_recorded.rs"]
mod health_alerts_recorded;
#[path = "imap_auth_webhooks_recorded.rs"]
mod imap_auth_webhooks_recorded;
#[path = "mail_workers_recorded.rs"]
mod mail_workers_recorded;
#[path = "migration_terminal_recorded.rs"]
mod migration_terminal_recorded;
#[path = "notify_drain_recorded.rs"]
mod notify_drain_recorded;
#[path = "push_drain_recorded.rs"]
mod push_drain_recorded;
#[path = "secevents_recorded.rs"]
mod secevents_recorded;
#[path = "smime_trust_recorded.rs"]
mod smime_trust_recorded;
#[path = "smtp_events_recorded.rs"]
mod smtp_events_recorded;
#[path = "spam_trainer_recorded.rs"]
mod spam_trainer_recorded;
#[path = "tls_rpt_recorded.rs"]
mod tls_rpt_recorded;
#[path = "webhook_workers_recorded.rs"]
mod webhook_workers_recorded;
