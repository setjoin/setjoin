//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[allow(dead_code)]
#[path = "support/auth_blobs.rs"]
pub mod auth_blobs;
#[allow(dead_code)]
#[path = "support/auth_dns.rs"]
pub mod auth_dns;
#[allow(clippy::if_same_then_else, dead_code)]
#[path = "../../../../bins/gateway/tests/common/commit.rs"]
pub mod commit;
#[allow(dead_code)]
#[path = "support/pipeline.rs"]
pub mod pipeline;
#[allow(dead_code)]
#[path = "support/outbound.rs"]
pub mod support;

#[path = "faults.rs"]
mod faults;
#[path = "fixture_expiry.rs"]
mod fixture_expiry;
#[path = "inbound_recording.rs"]
mod inbound_recording;
#[path = "mail_auth.rs"]
mod mail_auth;
#[path = "outbound.rs"]
mod outbound;
#[path = "outbound_lifecycle.rs"]
mod outbound_lifecycle;
#[path = "outbound_recording.rs"]
mod outbound_recording;
#[path = "pem_hot_reload.rs"]
mod pem_hot_reload;
#[path = "secfix_inbound.rs"]
mod secfix_inbound;
#[path = "session.rs"]
mod session;
#[path = "submission.rs"]
mod submission;
#[path = "transport.rs"]
mod transport;
#[path = "transport_dns.rs"]
mod transport_dns;
