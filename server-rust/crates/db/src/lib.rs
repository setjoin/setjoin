//! RP05 selected transaction lifecycle core. No database driver is linked here.
//!
//! This module checks transitions, comparison keys and recovery obligations. It
//! cannot establish current entitlement, durable operation state, database role,
//! SQL ownership, a held lock, or actual connection cleanliness. The RP05 driver
//! must supply those facts from trusted reads while its transaction fences hold.
//! Client-provided keys and enum observations are never authorization evidence.
#![forbid(unsafe_code)]

pub mod lifecycle;

#[cfg(test)]
mod tests;
