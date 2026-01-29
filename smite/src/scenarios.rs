/// `ScenarioInput` is a trait for scenario input types
pub trait ScenarioInput<'a>: Sized {
    /// Decode the input from a byte slice
    ///
    /// # Errors
    /// Returns an error if the bytes cannot be decoded into this input type.
    fn decode(bytes: &'a [u8]) -> Result<Self, String>;
}

/// `ScenarioResult` describes the outcomes of running a scenario
pub enum ScenarioResult {
    /// Scenario ran successfully
    Ok,
    /// Scenario indicated that the test case should be skipped
    Skip,
    /// Scenario indicated that the test case failed (i.e. the target node crashed)
    Fail(String),
}

/// `Scenario` is the interface for test scenarios that can be run against a target node
pub trait Scenario<'a, I>: Sized
where
    I: ScenarioInput<'a>,
{
    /// Create a new instance of the scenario, preparing the initial state of the test
    ///
    /// # Errors
    /// Returns an error if scenario initialization fails.
    fn new(args: &[String]) -> Result<Self, String>;
    /// Run the test with the given input
    fn run(&mut self, testcase: I) -> ScenarioResult;
}

/// Main entry point macro for smite scenarios.
///
/// Initializes the runner and scenario, then executes the fuzz input.
#[macro_export]
macro_rules! smite_main {
    ($scenario_type:ty, $testcase_type:ty) => {
        fn main() -> std::process::ExitCode {
            use std::process::ExitCode;
            use $crate::runners::{Runner, StdRunner};
            use $crate::scenarios::{Scenario, ScenarioInput, ScenarioResult};

            simple_logger::init_with_env().expect("Failed to initialize logger");

            // Initialize the runner before the scenario. This is important when
            // using Nyx to ensure nyx_init is called before spawning targets.
            let runner = StdRunner::new();

            let args: Vec<String> = std::env::args().collect();
            let mut scenario = match <$scenario_type>::new(&args) {
                Ok(scenario) => scenario,
                Err(e) => {
                    log::error!("Failed to initialize scenario: {e}");
                    let exit_code = std::env::var("SMITE_INIT_ERROR_EXIT_CODE")
                        .map_or(0, |v| v.parse().unwrap_or(0));
                    return ExitCode::from(exit_code);
                }
            };

            log::info!("Scenario initialized! Executing input...");

            // In Nyx mode the snapshot is taken here and a new fuzz input is provided each reset.
            let input = runner.get_fuzz_input();

            let Ok(testcase) = <$testcase_type>::decode(&input) else {
                log::warn!("Failed to decode test case!");
                runner.skip();
                return ExitCode::SUCCESS;
            };

            match scenario.run(testcase) {
                ScenarioResult::Ok => {}
                ScenarioResult::Skip => {
                    runner.skip();
                    return ExitCode::SUCCESS;
                }
                ScenarioResult::Fail(err) => {
                    runner.fail(&format!("Test case failed: {err}"));
                    return ExitCode::from(1);
                }
            }

            log::info!("Test case ran successfully!");

            // Drop runner before scenario. This provides a huge speedup in Nyx
            // mode since nyx_release() resets the VM before scenario cleanup
            // ever runs.
            drop(runner);

            ExitCode::SUCCESS
        }
    };
}
