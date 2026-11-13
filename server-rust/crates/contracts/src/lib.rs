//! RP02 selected contracts. Facts are trusted-store projections, never bearer authority.
//! No SQL, credentials, I/O, issuer, runtime, or cross-domain transaction implementation.
#![forbid(unsafe_code)]

pub mod authority;
pub mod command;
pub mod content;
pub mod error;
pub mod ids;
pub mod mutants;
pub mod recording;

pub mod csv;
pub mod han;
#[cfg(test)]
mod tests;

pub mod go_quote;
