//! LND IR fuzzing scenario binary, snapshotting with a channel already open.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::{IrScenario, PostChannelOpenSetup};
use smite_scenarios::targets::LndTarget;

fn main() -> std::process::ExitCode {
    smite_run::<IrScenario<LndTarget, PostChannelOpenSetup>>()
}
