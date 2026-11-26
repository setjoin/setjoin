//! `setjoin-server` legacy binary wrapper (#220, #142, #543).
//!
//! All runtime wiring lives in [`setjoin_gateway::runtime`] so `setjoin-server`
//! and `setjoind` share one implementation while keeping 100% of existing
//! `setjoin-server` CLI/env/test contracts intact until `#544`.

use std::process::ExitCode;

fn main() -> ExitCode {
    setjoin_gateway::runtime::run_legacy_cli()
}
