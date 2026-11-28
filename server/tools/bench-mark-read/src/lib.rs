//! `bench-mark-read` — the #217 mark-read comparison harness (evidence
//! tooling, never runtime authority). The binary drives one HTTP target with
//! a frozen request sequence; this library holds the logic its numbers
//! depend on, each piece tested on its own. Report:
//! `retired-docs:verification/2026-10-29-rp07-rust-vs-go-mark-read.md`.
pub mod http;
pub mod outcome;
pub mod plan;
pub mod procfs;
pub mod stats;
pub mod timeline;
