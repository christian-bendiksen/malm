//! Scores planned actions from low risk to blocked, escalating outside-home
//! writes and displacements.

use crate::fs::inspect::FilesystemPathState;
use crate::paths::{normalize_lexical, starts_with_home};
use crate::planning::evaluation::{PreviewAction, evaluate_plan_targets};
use crate::planning::plan::DeploymentPlan;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Blocked,
}

impl RiskLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Blocked => "BLOCKED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    CreateNew,
    RemoveStale,
    ReplaceSymlink,
    BackupFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskItem {
    pub level: RiskLevel,
    pub category: RiskCategory,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_flag: Option<&'static str>,
}

pub struct RiskReport {
    pub items: Vec<RiskItem>,
}

impl RiskReport {
    pub fn max_level(&self) -> Option<RiskLevel> {
        self.items.iter().map(|i| i.level).max()
    }

    pub fn has_blocked(&self) -> bool {
        self.items.iter().any(|i| i.level == RiskLevel::Blocked)
    }

    pub fn at_level(&self, level: RiskLevel) -> impl Iterator<Item = &RiskItem> {
        self.items.iter().filter(move |i| i.level == level)
    }

    pub fn needs_confirmation(&self) -> bool {
        self.items.iter().any(|i| {
            matches!(
                i.level,
                RiskLevel::Medium | RiskLevel::High | RiskLevel::Blocked
            )
        })
    }
}

pub fn assess_plan(plan: &DeploymentPlan) -> RiskReport {
    let entries = evaluate_plan_targets(plan);
    let mut items = Vec::new();

    for entry in &entries {
        let item = match entry.action {
            PreviewAction::Keep | PreviewAction::Error => continue,

            PreviewAction::Download => {
                let missing = matches!(entry.actual, FilesystemPathState::Missing);
                let outside_home = !starts_with_home(&normalize_lexical(&entry.target));
                let category = if missing {
                    RiskCategory::CreateNew
                } else {
                    RiskCategory::BackupFile
                };
                // Existence and the home boundary decide the level. Overwriting
                // an existing file outside home is always blocked.
                let (level, reason) = if outside_home && !missing {
                    (
                        RiskLevel::Blocked,
                        "displaces an existing file outside the home directory with a downloaded asset",
                    )
                } else if outside_home {
                    (
                        RiskLevel::High,
                        "installs a downloaded asset outside the home directory",
                    )
                } else if missing {
                    (RiskLevel::Low, "installs a new asset where nothing existed")
                } else {
                    (
                        RiskLevel::Medium,
                        "replaces an existing path with a downloaded asset",
                    )
                };
                RiskItem {
                    level,
                    category,
                    owner: entry.owner.clone(),
                    source: entry.source.clone(),
                    target: entry.target.clone(),
                    reason,
                    allow_flag: None,
                }
            }

            PreviewAction::Create => RiskItem {
                level: RiskLevel::Low,
                category: RiskCategory::CreateNew,
                owner: entry.owner.clone(),
                source: entry.source.clone(),
                target: entry.target.clone(),
                reason: "creates a new symlink where nothing existed",
                allow_flag: None,
            },

            PreviewAction::Remove => RiskItem {
                level: RiskLevel::Low,
                category: RiskCategory::RemoveStale,
                owner: entry.owner.clone(),
                source: entry.source.clone(),
                target: entry.target.clone(),
                reason: "removes a stale malm-owned symlink no longer in the config",
                allow_flag: None,
            },

            PreviewAction::Replace => match &entry.actual {
                FilesystemPathState::Symlink { .. } | FilesystemPathState::BrokenSymlink => {
                    RiskItem {
                        level: RiskLevel::Medium,
                        category: RiskCategory::ReplaceSymlink,
                        owner: entry.owner.clone(),
                        source: entry.source.clone(),
                        target: entry.target.clone(),
                        reason: "replaces an existing symlink pointing to a different target",
                        allow_flag: None,
                    }
                }
                FilesystemPathState::File | FilesystemPathState::Other => {
                    let outside_home = !starts_with_home(&normalize_lexical(&entry.target));
                    let (level, reason) = if outside_home {
                        (
                            RiskLevel::Blocked,
                            "displaces an existing file outside the home directory",
                        )
                    } else {
                        (
                            RiskLevel::Medium,
                            "displaces an existing file into the transaction backup directory",
                        )
                    };
                    RiskItem {
                        level,
                        category: RiskCategory::BackupFile,
                        owner: entry.owner.clone(),
                        source: entry.source.clone(),
                        target: entry.target.clone(),
                        reason,
                        allow_flag: None,
                    }
                }
                _ => continue,
            },
        };

        items.push(item);
    }

    RiskReport { items }
}
