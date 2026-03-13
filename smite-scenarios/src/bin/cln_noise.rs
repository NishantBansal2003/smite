//! CLN noise handshake fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::NoiseScenario;
use smite_scenarios::targets::ClnTarget;

fn main() -> std::process::ExitCode {
    smite_run::<NoiseScenario<ClnTarget>>()
}
