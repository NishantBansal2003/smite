use smite::scenarios::smite_run;
use smite_scenarios::scenarios::V1ChannelEstablishmentScenario;
use smite_scenarios::targets::LdkTarget;

fn main() -> std::process::ExitCode {
    smite_run::<V1ChannelEstablishmentScenario<LdkTarget>>()
}
