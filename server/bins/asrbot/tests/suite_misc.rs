//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod support;

#[path = "funasr_client.rs"]
mod funasr_client;
#[path = "outbound_oracle.rs"]
mod outbound_oracle;
#[path = "room_session.rs"]
mod room_session;
