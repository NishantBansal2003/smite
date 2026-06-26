//! Logger that forwards `log` records to the Nyx host via `nyx_println`.
//!
//! In Nyx mode the guest's stdout/stderr is discarded, so `simple_logger`
//! output never reaches the host. This logger instead routes each record
//! through `nyx_println` for debugging. Honors the `RUST_LOG` log level.
//!
//! This logger is only installed when the `nyx` feature is active and both
//! `SMITE_NYX` and `SMITE_NYX_LOG` are set.

use std::ffi::c_char;

use log::{LevelFilter, Log, Metadata, Record};

struct NyxLogger {
    level: LevelFilter,
}

impl Log for NyxLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{:<5} [{}] {}",
            record.level(),
            record.target(),
            record.args()
        );
        // SAFETY: The line.len() bytes at the line pointer are valid for the
        // duration of the call.
        unsafe {
            smite_nyx_sys::nyx_println(line.as_ptr().cast::<c_char>(), line.len());
        }
    }

    fn flush(&self) {}
}

/// Reads the desired level from `RUST_LOG` (default `info`).
fn level_from_env() -> LevelFilter {
    std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(LevelFilter::Info)
}

/// Installs the Nyx logger as the global `log` logger.
///
/// # Panics
///
/// Panics if a global logger has already been set.
pub fn init() {
    let level = level_from_env();
    log::set_boxed_logger(Box::new(NyxLogger { level })).expect("logger not already set");
    log::set_max_level(level);
}
