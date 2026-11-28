//! Consolidated integration test suite `suite_chat` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod chat_compliance_oracle;
#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
pub mod compliance_oracle;
#[allow(dead_code)]
#[path = "common/office_s3.rs"]
pub mod image_s3;
#[allow(dead_code)]
pub mod retention_audit_oracle;

#[path = "chat_b_recorded.rs"]
mod chat_b_recorded;
#[path = "chat_channels_recorded.rs"]
mod chat_channels_recorded;
#[path = "chat_compliance_recorded.rs"]
mod chat_compliance_recorded;
#[path = "chat_recorded.rs"]
mod chat_recorded;
#[path = "compliance_recorded.rs"]
mod compliance_recorded;
#[path = "retention_audit_recorded.rs"]
mod retention_audit_recorded;
