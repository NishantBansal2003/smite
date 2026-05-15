//! IR program scenario: deserialize a postcard `Program` from the fuzz input
//! and execute it against the target over an established encrypted connection.

use std::marker::PhantomData;

use smite::bitcoin::BitcoinCli;
use smite::noise::NoiseConnection;
use smite::scenarios::{Scenario, ScenarioError, ScenarioResult};
use smite_ir::Program;

use super::{SnapshotSetup, ping_pong};
use crate::executor::{self, ExecuteError, ProgramContext};
use crate::targets::Target;

/// Scenario that executes IR programs against a target over an encrypted
/// connection established by `S`.
pub struct IrScenario<T: Target, S: SnapshotSetup<T>> {
    target: T,
    conn: NoiseConnection,
    bitcoin_cli: BitcoinCli,
    context: ProgramContext,
    // S is only used for static dispatch on S::setup(), not stored.
    _phantom: PhantomData<S>,
}

impl<T: Target, S: SnapshotSetup<T>> Scenario for IrScenario<T, S> {
    fn new(_args: &[String]) -> Result<Self, ScenarioError> {
        let target = T::start(T::Config::default())?;
        let (conn, bitcoin_cli, context) = S::setup(&target)?;
        Ok(Self {
            target,
            conn,
            bitcoin_cli,
            context,
            _phantom: PhantomData,
        })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        let start = std::time::Instant::now();

        let Ok(program) = postcard::from_bytes::<Program>(input) else {
            log::debug!("Input did not deserialize properly, skipping");
            return ScenarioResult::Skip;
        };

        log::debug!(
            "[{:?}] Executing IR program ({} instructions, {} input bytes)",
            start.elapsed(),
            program.instructions.len(),
            input.len(),
        );

        match executor::execute(
            &program,
            &self.context,
            &mut self.conn,
            &mut self.bitcoin_cli,
            start,
        ) {
            Ok(()) => {
                log::debug!("[{:?}] Program executed successfully", start.elapsed());
            }
            Err(ExecuteError::Connection(e)) => {
                // Target may have closed the connection in response to bad
                // input. check_alive below is the authority on whether that's a
                // crash.
                log::debug!("[{:?}] execute connection error: {e}", start.elapsed());
            }
            Err(ExecuteError::UnexpectedMessage { expected, got }) => {
                // Target replied with an unexpected message type (often
                // Error/Warning when rejecting our input). Usually normal
                // protocol behavior.
                log::debug!(
                    "[{:?}] unexpected message: expected {expected}, got {got}",
                    start.elapsed(),
                );
            }
            Err(ExecuteError::Decode(e)) => {
                // Either our decoder is incomplete or the target sent something
                // the spec doesn't allow.
                return ScenarioResult::Fail(format!("decode error: {e}"));
            }
            Err(e) => {
                // Ill-formed IR program. This could happen if an input was
                // constructed manually or using non-Smite mutators.
                log::debug!("[{:?}] invalid IR program: {e}", start.elapsed());
                return ScenarioResult::Skip;
            }
        }

        // Ping-pong sync to ensure the target has at least done the initial
        // processing of all previous messages. Timeouts here signal a hang.
        if let Err(e) = ping_pong(&mut self.conn) {
            log::debug!("[{:?}] ping_pong: {e}", start.elapsed());
            if e.is_timeout() {
                return ScenarioResult::Fail("target hung (ping timeout)".into());
            }
        } else {
            log::debug!("[{:?}] Target responded with pong", start.elapsed());
        }

        if let Err(e) = self.target.check_alive() {
            log::debug!("[{:?}] check_alive: {e}", start.elapsed());
            return ScenarioResult::Fail("target crashed".into());
        }

        ScenarioResult::Ok
    }
}
