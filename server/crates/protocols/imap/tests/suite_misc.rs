//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;

#[path = "extra.rs"]
mod extra;
#[path = "hooks.rs"]
mod hooks;
#[path = "interop.rs"]
mod interop;
#[path = "interop_messages.rs"]
mod interop_messages;
#[path = "interop_session.rs"]
mod interop_session;
#[path = "messages_replay.rs"]
mod messages_replay;
#[path = "modseq_sync.rs"]
mod modseq_sync;
#[path = "password_policy.rs"]
mod password_policy;
#[path = "production_tls.rs"]
mod production_tls;
#[path = "replay.rs"]
mod replay;
#[path = "session_replay.rs"]
mod session_replay;
#[path = "threat_recorded.rs"]
mod threat_recorded;
