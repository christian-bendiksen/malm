//! Review and consent flow shared by `apply` and interactive `commit`.
//!
//! This module owns presentation and consent only. Callers retain mutation
//! authority and invoke `Engine::commit_v1`, keeping review policy outside the
//! Engine boundary. Consent places the plan's approval digest directly into
//! [`malm_types::ApprovalV1`], preserving the same byte-exact binding between
//! findings and plan as `commit PLAN_ID --approval DIGEST` without moving the
//! digest through a clipboard.

use std::io::{BufRead, IsTerminal};

use anyhow::Result;
use malm_types::{ApprovalV1, CommitRequestV1, PreparedDeploymentV1, PreparedId};

use crate::cli::output::Output;

/// A reviewer's decision for a newly prepared plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Consent {
    /// Commit now using the plan's approval digest.
    Commit,
    /// Return the requested durable plan without committing it (exit 0).
    PlanRequested,
    /// Leave the durable plan for a later manual commit (exit 1).
    PreparedOnly,
    /// Refuse `--yes` because findings require explicit approval (exit 2).
    ApprovalRequired,
}

impl Consent {
    /// Returns the exit code for a decision that does not commit.
    pub(super) const fn declined_exit_code(self) -> i32 {
        match self {
            Self::Commit | Self::PlanRequested => 0,
            Self::PreparedOnly => 1,
            Self::ApprovalRequired => 2,
        }
    }
}

/// Reviews a newly prepared plan and collects explicit consent.
///
/// The behavior is:
/// - `plan_only` prints the requested durable plan without prompting or
///   consenting, then exits 0 with instructions.
/// - `yes` consents without a prompt only when no finding requires approval.
///   Otherwise it prints the manual commit command and exits 2.
/// - An interactive terminal shows the full plan and findings, then prompts
///   with `[y/N]`. Only `y` consents; any other answer leaves the plan for review.
/// - A non-interactive call without `yes` prints the plan and manual commit
///   command, then exits 1. Scripts must opt in explicitly.
pub(super) fn review(
    plan: &PreparedDeploymentV1,
    plan_candidates: &[PreparedId],
    output: &Output,
    yes: bool,
    plan_only: bool,
) -> Result<Consent> {
    let approval_required = plan
        .findings()
        .iter()
        .filter(|finding| finding.approval_required())
        .count();

    if output.is_json() {
        if plan_only {
            super::deployment::print_plan_review(plan, plan_candidates, output, "planned")?;
            return Ok(Consent::PlanRequested);
        }
        if yes && approval_required == 0 {
            return Ok(Consent::Commit);
        }
        let (code, message) = if yes {
            (
                "approval-required",
                format!(
                    "approval required for {approval_required} finding(s); durable plan {} was not applied",
                    plan.plan_id()
                ),
            )
        } else {
            (
                "confirmation-required",
                format!(
                    "confirmation required; durable plan {} was not applied",
                    plan.plan_id()
                ),
            )
        };
        output.refusal(code, &message)?;
        return Ok(if yes {
            Consent::ApprovalRequired
        } else {
            Consent::PreparedOnly
        });
    }

    super::deployment::print_plan_review(plan, plan_candidates, output, "review")?;

    if plan_only {
        return Ok(Consent::PlanRequested);
    }
    if yes {
        if approval_required > 0 {
            print_manual_instructions(plan, plan_candidates, output, Some(approval_required))?;
            return Ok(Consent::ApprovalRequired);
        }
        return Ok(Consent::Commit);
    }

    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if !interactive {
        print_manual_instructions(plan, plan_candidates, output, None)?;
        return Ok(Consent::PreparedOnly);
    }

    if confirm(
        output,
        &consent_prompt(
            plan.namespace().as_str(),
            super::deployment::plan_changes_managed_targets(plan),
        ),
    )? {
        Ok(Consent::Commit)
    } else {
        print_manual_instructions(plan, plan_candidates, output, None)?;
        Ok(Consent::PreparedOnly)
    }
}

fn consent_prompt(namespace: &str, changes_managed_targets: bool) -> String {
    if changes_managed_targets {
        format!("Apply this plan to namespace \"{namespace}\"? [y/N] ")
    } else {
        format!(
            "Apply this plan to namespace \"{namespace}\" (updates namespace state only; no managed targets change)? [y/N] "
        )
    }
}

/// Builds a commit request with the reviewed plan's approval digest.
///
/// `malm-commit` still verifies the digest byte-for-byte against the durable record.
pub(super) fn consented_commit_request(plan: &PreparedDeploymentV1) -> CommitRequestV1 {
    CommitRequestV1::new(
        plan.plan_id().clone(),
        ApprovalV1::new(plan.plan_id().clone(), plan.approval_digest().clone()),
    )
}

fn print_manual_instructions(
    plan: &PreparedDeploymentV1,
    plan_candidates: &[PreparedId],
    output: &Output,
    refused_findings: Option<usize>,
) -> Result<()> {
    let mut rendered = String::from("\nNot applied\n");
    if let Some(count) = refused_findings {
        rendered.push_str(&format!(
            "  --yes cannot approve {count} approval-required finding(s).\n"
        ));
    } else {
        rendered.push_str("  The durable plan remains available for later review.\n");
    }
    rendered.push_str(&format!(
        "\nNext\n  malm plan apply {} --approval {}\n",
        super::ids::display_plan_unique(plan.plan_id(), plan_candidates, output.verbose()),
        plan.approval_digest()
    ));
    output.human(&rendered)
}

/// Reads one line of consent from the terminal.
///
/// Only `y`, `Y`, `yes`, or `YES` consents. EOF and all other input decline.
fn confirm(output: &Output, prompt: &str) -> Result<bool> {
    output.prompt(prompt)?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use super::consent_prompt;

    #[test]
    fn zero_target_change_prompt_explains_the_namespace_update() {
        assert_eq!(
            consent_prompt("default", false),
            "Apply this plan to namespace \"default\" (updates namespace state only; no managed targets change)? [y/N] "
        );
        assert_eq!(
            consent_prompt("default", true),
            "Apply this plan to namespace \"default\"? [y/N] "
        );
    }
}
