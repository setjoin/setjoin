//! F20 Assist and F22 static/health/metrics/telemetry domain logic (#271).
//!
//! Pure documents and decisions live here; the HTTP framing, security headers
//! and routing live in the gateway adapter. The crate depends on no other
//! family crate (the executor is `setjoin-pg`'s). Every function mirrors the
//! frozen Go handler named in its module header.
#![forbid(unsafe_code)]

pub mod assist;
pub mod downloads;
pub mod health;
pub mod metrics;
pub mod openapi;
pub mod wellknown;

pub mod website;

pub mod telemetry;
