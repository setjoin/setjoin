//! `setjoind` — unified Setjoin server executable (#543).

use std::process::ExitCode;

fn main() -> ExitCode {
    setjoind::run_cli()
}
