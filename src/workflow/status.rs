//! Reports drift with exit codes 0 for clean, 1 for drift, and 2 for unreadable
//! state. Disabled states are reported as deliberate.

use crate::app::context::GlobalCtx;
use crate::output::status::{print, to_json};
use crate::state::record::{StateMode, StateRecord, live_deployment_id};
use crate::state::state_namespaces;
use crate::status::ownership::evaluate;
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusExitCode {
    Ok = 0,
    Drift = 1,
    ConfigError = 2,
}

impl StatusExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}

pub fn run(ctx: &GlobalCtx, quiet: bool, verbose: bool) -> Result<StatusExitCode> {
    if let Some(StateMode::Disabled {
        restore_transaction,
        disabled_at,
        kept_targets,
    }) = StateRecord::load_for_state(ctx.state_namespace.as_str())?.map(|record| record.mode)
    {
        if !quiet {
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "state": ctx.state_namespace,
                        "disabled": true,
                        "disabled_at": disabled_at,
                        "restore_transaction": restore_transaction,
                        "kept_targets": kept_targets,
                    })
                );
            } else {
                use owo_colors::OwoColorize;
                let ns = ctx.state_namespace.as_str();
                println!(
                    "\n  {} state '{ns}' is disabled · {}",
                    "◌".dimmed(),
                    format!("`malm state enable {ns}` restores its previous deployment").dimmed(),
                );
            }
        }
        // Disabled is a deliberate, recorded condition, not drift.
        return Ok(StatusExitCode::Ok);
    }

    let report = match evaluate(ctx.state_namespace.as_str(), verbose) {
        Ok(report) => report,
        Err(error) => {
            if !quiet {
                crate::warn_term!("error reading ownership state: {error:#}");
            }
            return Ok(StatusExitCode::ConfigError);
        }
    };

    let nothing_to_report =
        report.is_empty() && report.source_pointer.is_ok() && report.target_lock.is_ok();

    if !quiet {
        if ctx.json {
            println!("{}", to_json(&report, ctx.state_namespace.as_str())?);
        } else if nothing_to_report {
            println!("Malm is not currently managing any configuration.");
        } else {
            let active_id = live_deployment_id(ctx.state_namespace.as_str())?
                .unwrap_or_else(|| "<none>".to_owned());
            print(&report, ctx.state_namespace.as_str(), &active_id, verbose);
        }
        if !ctx.json {
            print_other_states_hint(ctx.state_namespace.as_str());
        }
    }

    Ok(if report.has_drift {
        StatusExitCode::Drift
    } else {
        StatusExitCode::Ok
    })
}

fn print_other_states_hint(current: &str) {
    use owo_colors::OwoColorize;
    let Ok(names) = state_namespaces() else {
        return;
    };
    let others: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| *name != current)
        .collect();
    if others.is_empty() {
        return;
    }
    let noun = if others.len() == 1 {
        "other state"
    } else {
        "other states"
    };
    println!(
        "\n  {}",
        format!(
            "{} {noun}: {} · see `malm state list`",
            others.len(),
            others.join(", ")
        )
        .dimmed()
    );
}
