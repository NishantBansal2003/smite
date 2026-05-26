//! `smitebot` command-line interface.

mod commands;
mod utils;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use commands::{DoctorArgs, DoctorCommand};

#[derive(Debug, Parser)]
#[command(name = "smitebot", version, about = "Smite campaign manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate host prerequisites for running Smite campaigns.
    Doctor(DoctorArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let success = match cli.command {
        Commands::Doctor(args) => DoctorCommand::execute(&args),
    };

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
