//! Validates and dispatches CLI requests and maps their exit codes.

use anyhow::Result;
use clap::{Parser, error::ErrorKind};

use crate::cli::{Args, Cmd, Dispatch, OutputFormat, OutputOptions};

pub fn run() -> Result<i32> {
    let arguments = match Args::try_parse() {
        Ok(arguments) => arguments,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                crate::cli::output::write_parser_stdout(&error.to_string())?;
                return Ok(0);
            }
            if requests_json() {
                let output = crate::cli::output::Output::new(
                    "malm",
                    OutputOptions {
                        format: OutputFormat::Json,
                        ..OutputOptions::default()
                    },
                );
                output.invalid_request(&error.to_string())?;
            } else {
                crate::cli::output::write_parser_stderr(&error.to_string())?;
            }
            return Ok(error.exit_code());
        }
    };
    match arguments.into_dispatch() {
        Dispatch::Machine => crate::cli::machine::run(),
        Dispatch::Human(invocation) => {
            let output =
                crate::cli::output::Output::new(invocation.command_name, invocation.output);
            let contract = crate::cli::contracts::cli_contract(&invocation.command);
            let result = match &invocation.command {
                Cmd::Store { cmd } => crate::cli::store::run(cmd, &output).map(|()| 0),
                Cmd::Lock { cmd } => crate::cli::deployment::run_lock(cmd, &output).map(|()| 0),
                command => crate::cli::deployment::run(
                    command,
                    &output,
                    invocation.selected_profile.as_deref(),
                ),
            };
            match result.inspect(|_| {
                debug_assert_ne!(contract.effect().as_str(), "request-dependent");
            }) {
                Ok(code) => Ok(code),
                Err(error) => {
                    output.error(&error)?;
                    Ok(2)
                }
            }
        }
    }
}

fn requests_json() -> bool {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "machine")
    {
        return false;
    }
    arguments
        .iter()
        .enumerate()
        .skip(1)
        .take_while(|(_, argument)| *argument != "--")
        .any(|(index, argument)| {
            argument == "--format=json"
                || (argument == "--format"
                    && arguments
                        .get(index + 1)
                        .is_some_and(|value| value == "json"))
        })
}
