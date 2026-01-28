//! Fuzzing scenarios for Lightning Network implementations.
//!
//! This crate provides:
//! - [`Target`] trait abstracting over Lightning implementations (LND, CLN, LDK, etc.)
//! - Scenario implementations that work with any target
//! - Per-target binaries in `src/bin/`

pub mod scenarios;
pub mod targets;

pub use targets::{Target, TargetError};
