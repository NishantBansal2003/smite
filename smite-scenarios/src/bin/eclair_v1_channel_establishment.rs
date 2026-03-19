use smite::scenarios::smite_run;
use smite_scenarios::scenarios::V1ChannelEstablishmentScenario;
use smite_scenarios::targets::EclairTarget;

fn main() -> std::process::ExitCode {
    smite_run::<V1ChannelEstablishmentScenario<EclairTarget>>()
}
