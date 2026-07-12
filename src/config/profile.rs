//! Resolves the requested or default profile and its ancestor chain.

use crate::config::Config;
use crate::lang::resolve::linearize;
use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileSelection {
    None { explicit: bool },
    Named { active_names: Vec<String> },
}

impl ProfileSelection {
    pub fn resolve(cfg: &Config, requested: Option<&str>) -> Result<Self> {
        let Some(name) = requested_profile(cfg, requested) else {
            return Ok(Self::None {
                explicit: matches!(requested, Some("none")),
            });
        };

        let Some(chain) = linearize(&cfg.workspace, name) else {
            anyhow::bail!(
                "profile `{name}` not found (known profiles: {})",
                cfg.workspace.profile_names().join(", ")
            );
        };

        Ok(Self::Named {
            active_names: chain.iter().map(|p| p.name.clone()).collect(),
        })
    }

    pub fn active_names(&self) -> &[String] {
        match self {
            Self::None { .. } => &[],
            Self::Named { active_names, .. } => active_names,
        }
    }

    /// The selected (most-derived) profile.
    pub fn selected(&self) -> Option<&str> {
        self.active_names().last().map(String::as_str)
    }

    pub fn is_missing_default(&self) -> bool {
        matches!(self, Self::None { explicit: false })
    }

    /// Reject selecting an inheritance-only profile for an operation that
    /// materializes or plans outputs. Validation commands intentionally do
    /// not call this so abstract layers remain fully compiled by `check`.
    pub fn ensure_selectable(&self, cfg: &Config) -> Result<()> {
        let Some(name) = self.selected() else {
            return Ok(());
        };
        if cfg
            .workspace
            .profile(name)
            .is_some_and(|profile| profile.abstract_)
        {
            anyhow::bail!(
                "profile `{name}` is abstract and cannot be selected for plan, apply, or render"
            );
        }
        Ok(())
    }
}

fn requested_profile<'a>(cfg: &'a Config, requested: Option<&'a str>) -> Option<&'a str> {
    match requested {
        Some("none") => None,
        Some(name) => Some(name),
        None => cfg.settings.default_profile.as_deref(),
    }
}
