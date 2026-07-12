//! Restores the transaction recorded when a state was disabled. The checkout
//! finalizer clears the disabled marker after restoring the deployment.
//!
//! This restores the recorded deployment, not the current config. A later
//! `malm apply` reconciles any config changes.

use crate::app::context::GlobalCtx;
use crate::app::validation::validate_name;
use crate::domain::id::StateName;
use crate::state::ensure_state_exists;
use crate::state::record::{StateMode, StateRecord};
use crate::state::transaction::transaction_alias;
use crate::workflow::checkout;
use crate::workflow::disable::resolve_state_name;
use anyhow::Result;
use owo_colors::OwoColorize;

pub fn run(ctx: &GlobalCtx, name: Option<&str>, yes: bool, replace_kept: bool) -> Result<()> {
    let name = resolve_state_name(ctx, name, "enable")?;
    validate_name(name, "state name")?;
    ensure_state_exists(name)?;

    let Some(StateMode::Disabled {
        restore_transaction,
        kept_targets,
        ..
    }) = StateRecord::load_for_state(name)?.map(|record| record.mode)
    else {
        anyhow::bail!(
            "state '{name}' is not disabled; `malm state list` shows every state's status"
        );
    };

    // Targets kept by `disable --keep-modified` hold deliberate local edits;
    // restoring the recorded deployment would displace them.
    if !kept_targets.is_empty() && !replace_kept {
        let listing = kept_targets
            .iter()
            .map(|target| format!("    {}", crate::output::display::format_short_path(target)))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(
            "state '{name}' was disabled with --keep-modified and still holds {} modified \
             target(s):\n{listing}\n\
             re-run with --replace-kept to redeploy over them (the modified files are backed \
             up in the new transaction)",
            kept_targets.len()
        );
    }

    let mut enable_ctx = ctx.clone();
    enable_ctx.state_namespace = StateName::parse(name)?;

    // Checkout's finalizer records the restored deployment as Enabled.
    checkout::run(
        &enable_ctx,
        &restore_transaction,
        checkout::CheckoutOpts { yes, verify: false },
    )?;

    println!(
        "\n  {} enabled state '{name}' · {}",
        "✓".green().bold(),
        format!(
            "restored deployment {} — run `malm apply` to catch up with config changes",
            transaction_alias(&restore_transaction)
        )
        .dimmed()
    );
    Ok(())
}
