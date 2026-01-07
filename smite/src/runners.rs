#[cfg(feature = "nyx")]
use smite_nyx_sys::{nyx_fail, nyx_get_fuzz_input, nyx_init, nyx_release, nyx_skip};

/// `Runner` provides an abstraction for a smite test case runner (e.g. run under nyx,
/// local system for reproduction, etc.)
pub trait Runner {
    /// Initialize the runner
    fn new() -> Self;
    /// Get the next fuzz input
    fn get_fuzz_input(&self) -> Vec<u8>;
    /// Fail the last test case
    fn fail(&self, message: &str);
    /// Skip the last test case
    fn skip(&self);
}

/// `LocalRunner` reads fuzz input from the `SMITE_INPUT` environment variable path
/// or from stdin if the environment variable is not set.
///
/// Used for reproducing test cases locally without the Nyx hypervisor.
pub struct LocalRunner;

impl Runner for LocalRunner {
    fn new() -> Self {
        Self
    }

    fn get_fuzz_input(&self) -> Vec<u8> {
        use std::io::Read;
        if let Ok(path) = std::env::var("SMITE_INPUT") {
            log::info!("Reading input from {path:?}");
            std::fs::read(&path).unwrap_or_default()
        } else {
            log::info!("Reading input from /dev/stdin");
            let mut buffer = Vec::new();
            if let Err(e) = std::io::stdin().read_to_end(&mut buffer) {
                log::error!("Failed to read from stdin: {e}");
            }
            buffer
        }
    }

    fn fail(&self, message: &str) {
        log::error!("{message}");
    }

    fn skip(&self) {
        log::warn!("Skipping test case");
    }
}

#[cfg(feature = "nyx")]
pub struct NyxRunner {
    max_input_size: usize,
}

#[cfg(feature = "nyx")]
impl Runner for NyxRunner {
    fn new() -> Self {
        // SAFETY: nyx_init must be called exactly once before other nyx functions.
        // Calling it multiple times is undefined behavior. We rely on NyxRunner
        // being created only once via StdRunner.
        let max_input_size = unsafe { nyx_init() };
        Self { max_input_size }
    }

    fn get_fuzz_input(&self) -> Vec<u8> {
        let mut data = vec![0u8; self.max_input_size];
        // SAFETY: We pass a valid pointer to an allocated buffer of exactly
        // max_input_size bytes. The C code will write at most max_input_size
        // bytes and return the actual length written.
        let len = unsafe { nyx_get_fuzz_input(data.as_mut_ptr(), data.len()) };
        data.truncate(len);
        data
    }

    fn fail(&self, message: &str) {
        // SAFETY: nyx_fail expects a null-terminated C string. We use CString
        // to ensure null-termination. The pointer is valid for the call duration.
        let c_message = std::ffi::CString::new(message).unwrap_or_default();
        unsafe {
            nyx_fail(c_message.as_ptr());
        }
    }

    fn skip(&self) {
        // SAFETY: nyx_skip resets the VM to snapshot state. Safe to call after
        // nyx_init and nyx_get_fuzz_input have been called.
        unsafe {
            nyx_skip();
        }
    }
}

#[cfg(feature = "nyx")]
impl Drop for NyxRunner {
    fn drop(&mut self) {
        // SAFETY: nyx_release resets the VM to snapshot state and signals
        // completion to the fuzzer. Safe to call once at the end of a test case.
        unsafe {
            nyx_release();
        }
    }
}

#[cfg(feature = "nyx")]
type DefaultRunner = NyxRunner;
#[cfg(not(feature = "nyx"))]
type DefaultRunner = LocalRunner;

/// `StdRunner` automatically selects `NyxRunner` when the `nyx` feature is enabled,
/// otherwise falls back to `LocalRunner`.
pub struct StdRunner {
    runner: DefaultRunner,
}

impl Runner for StdRunner {
    fn new() -> Self {
        Self {
            runner: DefaultRunner::new(),
        }
    }

    fn get_fuzz_input(&self) -> Vec<u8> {
        self.runner.get_fuzz_input()
    }

    fn fail(&self, message: &str) {
        self.runner.fail(message);
    }

    fn skip(&self) {
        self.runner.skip();
    }
}
