//! Plan-wide compilation budgets. Counters accumulate across module instances,
//! outputs, loops, and artifacts. Exceeding a limit produces `MALM4001`.

use crate::lang::diag::{Diagnostic, codes};
use std::fmt;

/// Hard limits for one compilation.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum nesting depth of document structure and structural controls.
    pub max_control_nesting: usize,
    /// Maximum items in one list or keyed collection.
    pub max_collection_size: usize,
    /// Maximum iterations of a single `@for-range`.
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
            // One artifact may contain a wallpaper while the plan-wide limit
            // still bounds aggregate output.
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

/// Wraps [`Limits`] so [`Budget`]'s derived default receives `Limits::default()`.
#[derive(Debug)]
pub struct LimitsHolder(pub Limits);

#[allow(clippy::derivable_impls)] // Limits provides a custom default.
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

    pub(crate) fn limits(&self) -> &Limits {
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

    /// Charges `added` bytes and checks the artifact's new total length.
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

    /// Starts a bounded output whose bytes are not yet charged to the plan.
    ///
    /// Each append is checked immediately, but bytes are charged to the plan
    /// total only after serialization succeeds.
    pub(crate) fn begin_output(&self) -> OutputBudget {
        OutputBudget {
            limit: self.limits().max_artifact_bytes.min(
                self.limits()
                    .max_total_bytes
                    .saturating_sub(self.total_bytes),
            ),
            bytes: 0,
            exceeded: None,
        }
    }

    /// Charges a completed output or reports the append that crossed its limit.
    pub(crate) fn finish_output(&mut self, output: &OutputBudget, actual: usize) -> BudgetResult {
        if let Some(projected) = output.exceeded {
            return self.count_artifact_bytes(projected, projected);
        }
        debug_assert_eq!(u64::try_from(actual).ok(), Some(output.bytes));
        self.count_artifact_bytes(output.bytes, output.bytes)
    }

    /// Reserves one source-file read and returns the maximum number of bytes
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

    /// Checks a temporary buffer without charging it as final output.
    pub fn check_artifact_size(&mut self, bytes: u64) -> BudgetResult {
        if bytes > self.limits().max_artifact_bytes {
            return self.exceeded(format!(
                "artifact exceeds the per-file maximum of {} bytes",
                self.limits().max_artifact_bytes
            ));
        }
        Ok(())
    }

    /// Checks an artifact's projected final size without charging it.
    pub(crate) fn check_output_size(&mut self, bytes: u64) -> BudgetResult {
        if bytes > self.limits().max_artifact_bytes {
            return self.exceeded(format!(
                "artifact exceeds the per-file maximum of {} bytes",
                self.limits().max_artifact_bytes
            ));
        }
        if self
            .total_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > self.limits().max_total_bytes)
        {
            return self.exceeded(format!(
                "generated output exceeds the plan-wide maximum of {} bytes",
                self.limits().max_total_bytes
            ));
        }
        Ok(())
    }
}

/// Exact bytes belonging to one output while it is being serialized.
///
/// Separate strings may share this counter when a format has to retain parts
/// for ordering. Moving an already-accounted part into its final string must
/// use [`Self::append_accounted`] so those bytes are not charged twice.
#[derive(Debug)]
pub(crate) struct OutputBudget {
    limit: u64,
    bytes: u64,
    exceeded: Option<u64>,
}

impl OutputBudget {
    pub(crate) const fn exceeded(&self) -> bool {
        self.exceeded.is_some()
    }

    fn reserve(&mut self, bytes: usize) -> Option<()> {
        if self.exceeded.is_some() {
            return None;
        }
        let projected = self.bytes.saturating_add(u64::try_from(bytes).ok()?);
        if projected > self.limit {
            self.exceeded = Some(projected);
            return None;
        }
        self.bytes = projected;
        Some(())
    }

    pub(crate) fn push_str(&mut self, output: &mut String, value: &str) -> Option<()> {
        self.reserve(value.len())?;
        output.push_str(value);
        Some(())
    }

    pub(crate) fn push_char(&mut self, output: &mut String, value: char) -> Option<()> {
        self.reserve(value.len_utf8())?;
        output.push(value);
        Some(())
    }

    pub(crate) fn write_fmt(
        &mut self,
        output: &mut String,
        arguments: fmt::Arguments<'_>,
    ) -> Option<()> {
        fmt::write(&mut OutputWriter::new(self, output), arguments).ok()
    }

    pub(crate) fn writer<'a>(&'a mut self, output: &'a mut String) -> OutputWriter<'a> {
        OutputWriter::new(self, output)
    }

    pub(crate) fn append_accounted(output: &mut String, value: &str) {
        output.push_str(value);
    }

    pub(crate) fn pop(&mut self, output: &mut String) -> Option<char> {
        let value = output.pop()?;
        self.bytes -= value.len_utf8() as u64;
        Some(value)
    }

    pub(crate) fn remove_prefix(&mut self, output: &mut String, bytes: usize) {
        debug_assert!(output.is_char_boundary(bytes));
        output.drain(..bytes);
        self.bytes -= bytes as u64;
    }
}

/// A `fmt::Write` adapter that rejects an append before it exceeds the active
/// output limit. This lets third-party `Display` implementations write
/// directly into a bounded `String`.
pub(crate) struct OutputWriter<'a> {
    budget: &'a mut OutputBudget,
    output: &'a mut String,
}

impl<'a> OutputWriter<'a> {
    fn new(budget: &'a mut OutputBudget, output: &'a mut String) -> Self {
        Self { budget, output }
    }
}

impl fmt::Write for OutputWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.budget.push_str(self.output, value).ok_or(fmt::Error)
    }

    fn write_char(&mut self, value: char) -> fmt::Result {
        self.budget.push_char(self.output, value).ok_or(fmt::Error)
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

    #[test]
    fn bounded_output_checks_while_writing_and_commits_once() {
        use std::fmt::Write as _;

        let limits = Limits {
            max_artifact_bytes: 4,
            max_total_bytes: 6,
            ..Limits::default()
        };
        let mut budget = Budget::new(limits);
        let mut first = budget.begin_output();
        let mut content = String::new();
        write!(first.writer(&mut content), "abcd").unwrap();
        budget.finish_output(&first, content.len()).unwrap();
        assert_eq!(content, "abcd");

        let mut second = budget.begin_output();
        let mut content = String::new();
        assert!(write!(second.writer(&mut content), "abc").is_err());
        assert_eq!(content, "", "the crossing append must not be retained");
        assert!(budget.finish_output(&second, content.len()).is_err());
        assert!(budget.exhausted());
    }
}
