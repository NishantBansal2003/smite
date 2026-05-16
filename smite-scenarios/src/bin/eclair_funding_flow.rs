//! Eclair funding-flow scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::{FundingFlowScenario, PostInitSetup};
use smite_scenarios::targets::EclairTarget;

fn main() -> std::process::ExitCode {
    smite_run::<FundingFlowScenario<EclairTarget, PostInitSetup>>()
}
