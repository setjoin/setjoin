//! Consolidated integration test suite `suite_calendar_mail` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod calendar_oracle;
#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
pub mod contacts_oracle;
#[allow(dead_code)]
pub mod mailbox_io_oracle;
#[allow(dead_code)]
pub mod mailboxes_oracle;
#[allow(dead_code)]
pub mod migration_oracle;
#[allow(dead_code)]
pub mod offline_oracle;
#[allow(dead_code)]
pub mod rules_oracle;

#[path = "calendar.rs"]
mod calendar;
#[path = "contacts.rs"]
mod contacts;
#[path = "mailbox_io.rs"]
mod mailbox_io;
#[path = "mailboxes.rs"]
mod mailboxes;
#[path = "migration.rs"]
mod migration;
#[path = "offline.rs"]
mod offline;
#[path = "rules.rs"]
mod rules;
