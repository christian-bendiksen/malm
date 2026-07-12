//! Human rendering of policy findings, grouped by category with blocked
//! findings listed before reviewable ones.

use crate::output::display::{common_ancestor, format_short_path};
use crate::policy::PolicyFinding;
use crate::sanitize::terminal;
use owo_colors::OwoColorize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct PolicyBucket {
    blocked: usize,
    target_paths: Vec<PathBuf>,
    target_labels: Vec<String>,
    reasons: BTreeSet<&'static str>,
    allow_flags: BTreeSet<&'static str>,
}

pub fn print_policy_violations(violations: &[PolicyFinding]) {
    if violations.is_empty() {
        return;
    }

    let mut buckets: BTreeMap<&'static str, PolicyBucket> = BTreeMap::new();
    for finding in violations {
        let bucket = buckets.entry(finding.category.label()).or_default();
        if finding.is_block() {
            bucket.blocked += 1;
        }
        match &finding.target {
            Some(path) => bucket.target_paths.push(path.clone()),
            None => bucket
                .target_labels
                .push(terminal(&finding.owner).into_owned()),
        }
        bucket.reasons.insert(finding.reason);
        if !finding.allow_flag.is_empty() {
            bucket.allow_flags.insert(finding.allow_flag);
        }
    }

    let blocked = violations.iter().filter(|f| f.is_block()).count();
    let reviewable = violations.len() - blocked;

    println!(
        "\n  {}  {}",
        "POLICY".bold(),
        summary(blocked, reviewable).dimmed()
    );
    println!();

    for (category, bucket) in buckets.iter().filter(|(_, bucket)| bucket.blocked > 0) {
        print_row(category, bucket, true);
    }
    for (category, bucket) in buckets.iter().filter(|(_, bucket)| bucket.blocked == 0) {
        print_row(category, bucket, false);
    }

    if blocked > 0 {
        let flags: Vec<&str> = buckets
            .values()
            .flat_map(|bucket| bucket.allow_flags.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if flags.is_empty() {
            println!(
                "\n  {} blocked — these paths cannot be managed remotely",
                "✗".red().bold()
            );
        } else {
            println!(
                "\n  {} blocked — re-run with: {}",
                "✗".red().bold(),
                flags.join(" ").cyan()
            );
        }
    }
}

fn summary(blocked: usize, reviewable: usize) -> String {
    if blocked > 0 {
        format!("{blocked} blocked · {reviewable} reviewable")
    } else {
        format!("{reviewable} reviewable")
    }
}

fn print_row(category: &str, bucket: &PolicyBucket, block: bool) {
    let badge = if block {
        format!("{:<8}", "block").red().bold().to_string()
    } else {
        format!("{:<8}", "review").yellow().to_string()
    };
    let label = format!("{category:<31}");
    println!("     {badge} {label}{}", scope(bucket).dimmed());

    if block {
        let reason = bucket
            .reasons
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .join("; ");
        let flags = bucket
            .allow_flags
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if flags.is_empty() {
            println!("              {}", reason.dimmed());
        } else {
            println!("              {} · pass {}", reason.dimmed(), flags.cyan());
        }
    }
}

fn scope(bucket: &PolicyBucket) -> String {
    if !bucket.target_paths.is_empty() {
        if bucket.target_paths.len() == 1 {
            return format_short_path(&bucket.target_paths[0]);
        }
        let refs: Vec<&Path> = bucket.target_paths.iter().map(PathBuf::as_path).collect();
        return format!(
            "{}   {} paths",
            format_short_path(&common_ancestor(&refs)),
            bucket.target_paths.len()
        );
    }
    if !bucket.target_labels.is_empty() {
        let mut labels = bucket.target_labels.clone();
        labels.sort();
        labels.dedup();
        return labels.join(", ");
    }
    "-".to_owned()
}
