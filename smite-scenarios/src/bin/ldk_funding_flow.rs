//! LDK funding-flow scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::{FundingFlowScenario, PostInitSetup};
use smite_scenarios::targets::LdkTarget;

fn main() -> std::process::ExitCode {
    smite_run::<FundingFlowScenario<LdkTarget, PostInitSetup>>()
}
