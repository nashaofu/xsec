use std::process::ExitCode;

use clap::Parser;

use crate::{cli::Cli, commands::execute};

mod cli;
mod commands;
mod environment;
mod error;
mod file;
mod storage;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
