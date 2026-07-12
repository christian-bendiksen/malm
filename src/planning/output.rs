//! Limits and deterministic matching for filesystem-backed outputs.

use crate::lang::budget::Limits;
use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;

pub(crate) fn compile_ignore_patterns(patterns: &[String]) -> Result<Option<globset::GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = globset::GlobSetBuilder::new();
    for pattern in patterns {
        let glob = globset::Glob::new(pattern)
            .with_context(|| format!("invalid ignore pattern `{pattern}`"))?;
        builder.add(glob);
    }
    Ok(Some(builder.build().context("compile ignore patterns")?))
}

pub(crate) struct OutputBudget {
    limits: Limits,
    directory_entries: usize,
    output_bytes: u64,
    exhausted: bool,
}

impl OutputBudget {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            directory_entries: 0,
            output_bytes: 0,
            exhausted: false,
        }
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted
    }

    pub(crate) fn count_directory_entry(&mut self) -> Result<()> {
        let Some(next) = self.directory_entries.checked_add(1) else {
            self.exhausted = true;
            anyhow::bail!("directory-entry counter overflowed");
        };
        if next > self.limits.max_directory_entries {
            self.exhausted = true;
            anyhow::bail!(
                "directory outputs exceed the plan-wide maximum of {} entries",
                self.limits.max_directory_entries
            );
        }
        self.directory_entries = next;
        Ok(())
    }

    pub(crate) fn count_output_file(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.limits.max_artifact_bytes {
            self.exhausted = true;
            anyhow::bail!(
                "output file exceeds the maximum of {} bytes",
                self.limits.max_artifact_bytes
            );
        }
        let Some(total) = self.output_bytes.checked_add(bytes) else {
            self.exhausted = true;
            anyhow::bail!("output-byte counter overflowed");
        };
        if total > self.limits.max_total_bytes {
            self.exhausted = true;
            anyhow::bail!(
                "rendered outputs exceed the plan-wide maximum of {} bytes",
                self.limits.max_total_bytes
            );
        }
        self.output_bytes = total;
        Ok(())
    }

    /// Read at most the bytes still permitted for one output and for the
    /// aggregate output set. The extra byte detects growth after metadata was
    /// inspected without allowing an unbounded allocation.
    pub(crate) fn read_output_file(&mut self, path: &Path) -> Result<Vec<u8>> {
        if self.exhausted {
            anyhow::bail!("output budget is already exhausted");
        }
        let mut file =
            std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let remaining = self.limits.max_total_bytes - self.output_bytes;
        let allowance = remaining.min(self.limits.max_artifact_bytes);
        if file
            .metadata()
            .ok()
            .is_some_and(|meta| meta.len() > allowance)
        {
            self.exhausted = true;
            anyhow::bail!(
                "output source {} exceeds the remaining output budget of {allowance} bytes",
                path.display()
            );
        }
        let mut content = Vec::new();
        file.by_ref()
            .take(allowance.saturating_add(1))
            .read_to_end(&mut content)
            .with_context(|| format!("read {}", path.display()))?;
        self.count_output_file(content.len() as u64)?;
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_globs_are_errors() {
        let error = compile_ignore_patterns(&["[".to_owned()]).unwrap_err();
        assert!(error.to_string().contains("invalid ignore pattern"));
    }

    #[test]
    fn directory_and_output_limits_are_aggregate() {
        let limits = Limits {
            max_directory_entries: 2,
            max_artifact_bytes: 3,
            max_total_bytes: 4,
            ..Limits::default()
        };
        let mut budget = OutputBudget::new(limits);

        budget.count_directory_entry().unwrap();
        budget.count_directory_entry().unwrap();
        assert!(budget.count_directory_entry().is_err());

        let mut budget = OutputBudget::new(limits);
        budget.count_output_file(3).unwrap();
        assert!(budget.count_output_file(2).is_err());
        assert!(budget.exhausted());
    }

    #[test]
    fn source_read_is_bounded_before_allocation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("large");
        std::fs::write(&path, b"12345").unwrap();
        let limits = Limits {
            max_artifact_bytes: 4,
            max_total_bytes: 4,
            ..Limits::default()
        };
        let mut budget = OutputBudget::new(limits);

        assert!(budget.read_output_file(&path).is_err());
        assert!(budget.exhausted());
    }
}
