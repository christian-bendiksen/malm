//! Plan-wide compilation budgets. Counters accumulate across module instances,
//! outputs, loops, and artifacts. Exceeding a limit produces `MALM4001`.

use crate::lang::diag::{Diagnostic, codes};

/// Hard limits for one compilation.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum nesting depth of document structure and structural controls.
    pub max_control_nesting: usize,
    /// Maximum items in one list or keyed collection.
    pub max_collection_size: usize,
    /// Maximum iterations of a single `range`.
    pub max_range_iterations: i64,
    /// Maximum total loop iterations across the whole plan.
    pub max_total_iterations: u64,
    /// Maximum KDL nodes generated across the whole plan.
    pub max_generated_nodes: u64,
    /// Maximum emit/serialize operations across the whole plan.
    pub max_operations: u64,
    /// Maximum bytes of one generated artifact.
    pub max_artifact_bytes: u64,
    /// Maximum bytes generated across the whole plan.
    pub max_total_bytes: u64,
    /// Maximum files readable during rendering (fragments + emit-file).
    pub max_render_files: usize,
    /// Maximum bytes readable during rendering.
    pub max_render_bytes: u64,
    /// Maximum entries when walking a `dir` output.
    pub max_directory_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_control_nesting: 16,
            max_collection_size: 4096,
            max_range_iterations: 10_000,
            max_total_iterations: 100_000,
            max_generated_nodes: 1_000_000,
            max_operations: 1_000_000,
            // Leave room for repositories that include wallpapers and themes.
            max_artifact_bytes: 64 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
            max_render_files: 1024,
            max_render_bytes: 16 * 1024 * 1024,
            max_directory_entries: 10_000,
        }
    }
}

/// Accumulating counters checked against [`Limits`].
#[derive(Debug, Default)]
pub struct Budget {
    pub limits: LimitsHolder,
    total_iterations: u64,
    generated_nodes: u64,
    operations: u64,
    total_bytes: u64,
    render_files: usize,
    render_bytes: u64,
    exhausted: bool,
}

/// Gives `Budget::default()` the standard limits.
#[derive(Debug)]
pub struct LimitsHolder(pub Limits);

#[allow(clippy::derivable_impls)] // Limits has a manual Default implementation.
impl Default for LimitsHolder {
    fn default() -> Self {
        Self(Limits::default())
    }
}

/// A budget violation that can be reported at the call site.
#[derive(Debug)]
pub struct BudgetError {
    pub what: String,
}

impl BudgetError {
    pub fn into_diagnostic(self) -> Diagnostic {
        Diagnostic::error(codes::BUDGET, self.what)
            .with_help("budgets bound total expansion work across the whole plan; reduce loop sizes or split outputs")
    }
}

type BudgetResult = Result<(), BudgetError>;

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits: LimitsHolder(limits),
            ..Self::default()
        }
    }

    fn limits(&self) -> &Limits {
        &self.limits.0
    }

    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    fn exceeded(&mut self, what: impl Into<String>) -> BudgetResult {
        self.exhausted = true;
        Err(BudgetError { what: what.into() })
    }

    pub fn check_nesting(&mut self, depth: usize) -> BudgetResult {
        if depth > self.limits().max_control_nesting {
            return self.exceeded(format!(
                "control nesting exceeds the maximum of {}",
                self.limits().max_control_nesting
            ));
        }
        Ok(())
    }

    pub fn check_collection_size(&mut self, len: usize) -> BudgetResult {
        if len > self.limits().max_collection_size {
            return self.exceeded(format!(
                "collection has {len} items, exceeding the maximum of {}",
                self.limits().max_collection_size
            ));
        }
        Ok(())
    }

    pub fn check_range(&mut self, iterations: i64) -> BudgetResult {
        if iterations > self.limits().max_range_iterations {
            return self.exceeded(format!(
                "range spans {iterations} iterations, exceeding the maximum of {}",
                self.limits().max_range_iterations
            ));
        }
        Ok(())
    }

    pub fn count_iterations(&mut self, n: u64) -> BudgetResult {
        let Some(total) = self.total_iterations.checked_add(n) else {
            return self.exceeded("total iteration counter overflowed");
        };
        if total > self.limits().max_total_iterations {
            return self.exceeded(format!(
                "total loop iterations exceed the plan-wide maximum of {}",
                self.limits().max_total_iterations
            ));
        }
        self.total_iterations = total;
        Ok(())
    }

    pub fn count_generated_nodes(&mut self, n: u64) -> BudgetResult {
        let Some(total) = self.generated_nodes.checked_add(n) else {
            return self.exceeded("generated-node counter overflowed");
        };
        if total > self.limits().max_generated_nodes {
            return self.exceeded(format!(
                "generated KDL nodes exceed the plan-wide maximum of {}",
                self.limits().max_generated_nodes
            ));
        }
        self.generated_nodes = total;
        Ok(())
    }

    pub fn count_operations(&mut self, n: u64) -> BudgetResult {
        let Some(total) = self.operations.checked_add(n) else {
            return self.exceeded("operation counter overflowed");
        };
        if total > self.limits().max_operations {
            return self.exceeded(format!(
                "operations exceed the plan-wide maximum of {}",
                self.limits().max_operations
            ));
        }
        self.operations = total;
        Ok(())
    }

    /// Count an artifact's new total length and the bytes added.
    pub fn count_artifact_bytes(&mut self, artifact_len: u64, added: u64) -> BudgetResult {
        if artifact_len > self.limits().max_artifact_bytes {
            return self.exceeded(format!(
                "artifact exceeds the per-file maximum of {} bytes",
                self.limits().max_artifact_bytes
            ));
        }
        let Some(total) = self.total_bytes.checked_add(added) else {
            return self.exceeded("generated-bytes counter overflowed");
        };
        if total > self.limits().max_total_bytes {
            return self.exceeded(format!(
                "generated output exceeds the plan-wide maximum of {} bytes",
                self.limits().max_total_bytes
            ));
        }
        self.total_bytes = total;
        Ok(())
    }

    /// Reserve one source-file read and return the maximum number of bytes
    /// that may be read from it without exceeding the aggregate limit.
    pub fn begin_render_file(&mut self) -> Result<u64, BudgetError> {
        let Some(files) = self.render_files.checked_add(1) else {
            self.exhausted = true;
            return Err(BudgetError {
                what: "render file counter overflowed".to_owned(),
            });
        };
        if files > self.limits().max_render_files {
            self.exhausted = true;
            return Err(BudgetError {
                what: format!(
                    "rendering read more than {} source files",
                    self.limits().max_render_files
                ),
            });
        }
        self.render_files = files;
        Ok(self.limits().max_render_bytes - self.render_bytes)
    }

    pub fn count_render_bytes(&mut self, bytes: u64) -> BudgetResult {
        let Some(total) = self.render_bytes.checked_add(bytes) else {
            return self.exceeded("render byte counter overflowed");
        };
        if total > self.limits().max_render_bytes {
            return self.exceeded(format!(
                "rendering read more than {} source bytes",
                self.limits().max_render_bytes
            ));
        }
        self.render_bytes = total;
        Ok(())
    }

    /// Check a temporary buffer without adding it to final output bytes.
    pub fn check_artifact_size(&mut self, bytes: u64) -> BudgetResult {
        if bytes > self.limits().max_artifact_bytes {
            return self.exceeded(format!(
                "artifact exceeds the per-file maximum of {} bytes",
                self.limits().max_artifact_bytes
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_budget_is_reserved_before_mutation_and_then_exhausted() {
        let limits = Limits {
            max_artifact_bytes: 3,
            max_total_bytes: 4,
            ..Limits::default()
        };
        let mut budget = Budget::new(limits);

        budget.count_artifact_bytes(2, 2).unwrap();
        assert!(budget.count_artifact_bytes(4, 2).is_err());
        assert_eq!(budget.total_bytes, 2, "failed reservation must not count");
        assert!(budget.exhausted());
    }

    #[test]
    fn render_reads_are_aggregate() {
        let limits = Limits {
            max_render_files: 2,
            max_render_bytes: 3,
            ..Limits::default()
        };
        let mut budget = Budget::new(limits);

        assert_eq!(budget.begin_render_file().unwrap(), 3);
        budget.count_render_bytes(2).unwrap();
        assert_eq!(budget.begin_render_file().unwrap(), 1);
        assert!(budget.count_render_bytes(2).is_err());
        assert!(budget.exhausted());
    }
}
