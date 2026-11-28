//! Consolidated integration test suite `suite_serial_mailsec_jmap` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
pub mod divfix;
#[allow(dead_code)]
pub mod drain_oracle;
#[allow(dead_code)]
pub mod exchange_oracle;
#[allow(dead_code, unused_imports)]
pub mod jmap_email_oracle;
#[allow(dead_code, unused_imports)]
pub mod mailsec_oracle;

#[path = "exchange.rs"]
mod exchange;
#[path = "jmap_email.rs"]
mod jmap_email;
#[path = "jmap_messages.rs"]
mod jmap_messages;
#[path = "jmap_other.rs"]
mod jmap_other;
#[path = "jmap_recorded.rs"]
mod jmap_recorded;
#[path = "jmap_submission.rs"]
mod jmap_submission;
#[path = "mailsec_dlp.rs"]
mod mailsec_dlp;
#[path = "mailsec_dmarc.rs"]
mod mailsec_dmarc;
#[path = "mailsec_linkprotect.rs"]
mod mailsec_linkprotect;
#[path = "mailsec_quarantine.rs"]
mod mailsec_quarantine;
#[path = "mailsec_queue.rs"]
mod mailsec_queue;
#[path = "mailsec_smime.rs"]
mod mailsec_smime;
#[path = "mailsec_spam.rs"]
mod mailsec_spam;
#[path = "mailsec_threat.rs"]
mod mailsec_threat;
#[path = "mailsec_tls.rs"]
mod mailsec_tls;
#[path = "mailsec_trace.rs"]
mod mailsec_trace;
