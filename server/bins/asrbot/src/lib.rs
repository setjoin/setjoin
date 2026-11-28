//! `setjoin-asrbot`: the Meet captions room-bot sidecar. Contract: [DOX.md](../DOX.md).
#![deny(unsafe_code)]

pub mod config;
pub mod control;
pub mod funasr;
pub mod gojson;
pub mod livekit;
pub mod log;
pub mod opus;
pub mod registry;
pub mod serve;
pub mod session;
pub mod vad;
pub mod worker;
pub mod wsdial;
