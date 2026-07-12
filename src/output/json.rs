//! JSON contract for `plan --json`.

use crate::planning::evaluation::{PreviewAction, evaluate_plan_targets};
use crate::planning::plan::DeploymentPlan;
use crate::policy::PolicyFinding;
use crate::policy::risk::{RiskItem, assess_plan};
use std::path::Path;

pub fn plan_to_json(plan: &DeploymentPlan, violations: &[PolicyFinding]) -> anyhow::Result<String> {
    use serde_json::{Value, json};

    let entries = evaluate_plan_targets(plan);
    let risk = assess_plan(plan);

    let risk_by_target: std::collections::HashMap<&Path, &RiskItem> = risk
        .items
        .iter()
        .map(|item| (item.target.as_path(), item))
        .collect();

    let mut create = 0usize;
    let mut keep = 0usize;
    let mut replace = 0usize;
    let mut remove = 0usize;
    let mut error_count = plan.errors().len();

    // Download counts as a create; Error feeds error_count, not a change
    // bucket.
    let operations: Vec<Value> = entries
        .iter()
        .map(|e| {
            let action = match e.action {
                PreviewAction::Keep => {
                    keep += 1;
                    "keep"
                }
                PreviewAction::Create => {
                    create += 1;
                    "create"
                }
                PreviewAction::Replace => {
                    replace += 1;
                    "replace"
                }
                PreviewAction::Remove => {
                    remove += 1;
                    "remove"
                }
                PreviewAction::Download => {
                    create += 1;
                    "download"
                }
                PreviewAction::Error => {
                    error_count += 1;
                    "error"
                }
            };

            let risk_level = risk_by_target
                .get(e.target.as_path())
                .map(|r| r.level.label())
                .unwrap_or("none");
            let risk_reason = risk_by_target
                .get(e.target.as_path())
                .map(|r| r.reason)
                .unwrap_or("");

            let mut v = json!({
                "action": action,
                "owner": e.owner,
                "target": e.target,
                "risk_level": risk_level,
            });
            if let Some(ref src) = e.source {
                v["source"] = json!(src);
            }
            if !risk_reason.is_empty() {
                v["risk_reason"] = json!(risk_reason);
            }
            v
        })
        .collect();

    let policy_violations: Vec<Value> = violations
        .iter()
        .map(|v| {
            json!({
                "category": v.category.label(),
                "severity": if v.is_block() { "block" } else { "notice" },
                "target": v.target.as_ref().map(|p| p.display().to_string()),
                "reason": v.reason,
                "allow_flag": (!v.allow_flag.is_empty()).then_some(v.allow_flag),
            })
        })
        .collect();
    let has_blocks = violations.iter().any(|v| v.is_block());
    let mut required_flags: Vec<&str> = violations
        .iter()
        .filter(|v| v.is_block())
        .map(|v| v.allow_flag)
        .filter(|f| !f.is_empty())
        .collect();
    required_flags.sort_unstable();
    required_flags.dedup();

    Ok(serde_json::to_string_pretty(&json!({
        "operations": operations,
        "errors": plan.errors(),
        "warnings": plan.warnings(),
        "summary": {
            "create": create,
            "keep": keep,
            "replace": replace,
            "remove": remove,
            "error": error_count,
            "warnings": plan.warnings().len(),
        },
        "risk": {
            "items": risk.items,
            "max_level": risk.max_level().map(|l| l.label()),
            "needs_confirmation": risk.needs_confirmation(),
        },
        "remote_policy": {
            "violations": policy_violations,
            "blocked": has_blocks,
            "required_flags": required_flags,
        },
    }))?)
}
