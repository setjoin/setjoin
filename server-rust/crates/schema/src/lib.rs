//! Canonical SQL migration catalog shared by standalone server binaries.
#![forbid(unsafe_code)]
include!(concat!(env!("OUT_DIR"), "/migrations.rs"));
