//! Standalone build of the same TCP and UDP test commands used by netprobe.
#[path = "../rust/lanewayd/src/inspect_probe_main/stream.rs"]
mod stream;

use std::process::ExitCode;

fn main() -> ExitCode {
    match stream::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("netprobe: {error}");
            ExitCode::FAILURE
        }
    }
}
