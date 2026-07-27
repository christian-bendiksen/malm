//! Structured diagnostics with stable codes, source spans, labels, and help.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Interned source file id inside a [`SourceMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub(crate) usize);

/// A byte range inside one source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub file: FileId,
    pub offset: usize,
    pub len: usize,
}

impl Span {
    pub fn new(file: FileId, offset: usize, len: usize) -> Self {
        Self { file, offset, len }
    }
}

#[derive(Debug)]
struct SourceFile {
    path: PathBuf,
    text: Arc<str>,
    /// The include chain that led to this file (outermost first), as
    /// human-readable paths. Empty for the root config.
    include_chain: Vec<PathBuf>,
}

/// Loaded source files used to render diagnostic excerpts.
#[derive(Debug, Default)]
pub struct SourceMap {
    files: Vec<SourceFile>,
}

impl SourceMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(
        &mut self,
        path: PathBuf,
        text: impl Into<Arc<str>>,
        include_chain: Vec<PathBuf>,
    ) -> FileId {
        self.files.push(SourceFile {
            path,
            text: text.into(),
            include_chain,
        });
        FileId(self.files.len() - 1)
    }

    pub fn path(&self, file: FileId) -> &Path {
        &self.files[file.0].path
    }

    pub fn text(&self, file: FileId) -> &str {
        &self.files[file.0].text
    }

    pub fn include_chain(&self, file: FileId) -> &[PathBuf] {
        &self.files[file.0].include_chain
    }

    /// Returns the one-based line and column for a byte offset.
    fn line_col(&self, file: FileId, offset: usize) -> (usize, usize) {
        let text = self.text(file);
        let clamped = offset.min(text.len());
        let mut line = 1usize;
        let mut line_start = 0usize;
        for (idx, byte) in text.bytes().enumerate() {
            if idx >= clamped {
                break;
            }
            if byte == b'\n' {
                line += 1;
                line_start = idx + 1;
            }
        }
        (line, clamped - line_start + 1)
    }

    fn line_text(&self, file: FileId, line: usize) -> &str {
        self.text(file).lines().nth(line - 1).unwrap_or("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// A secondary annotation pointing at related source (e.g. "input declared
/// here").
#[derive(Debug, Clone)]
pub struct Label {
    pub message: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Stable `MALM####` code.
    pub code: &'static str,
    pub message: String,
    pub span: Option<Span>,
    pub labels: Vec<Label>,
    pub help: Option<String>,
    /// Extra provenance lines (module instance, profile, expansion trace).
    pub notes: Vec<String>,
}

impl Diagnostic {
    pub fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code,
            message: message.into(),
            span: None,
            labels: Vec::new(),
            help: None,
            notes: Vec::new(),
        }
    }

    /// Construct a warning diagnostic.
    #[allow(dead_code)]
    pub fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            ..Self::error(code, message)
        }
    }

    pub fn with_span(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }

    pub fn with_label(mut self, message: impl Into<String>, span: Span) -> Self {
        self.labels.push(Label {
            message: message.into(),
            span,
        });
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Render the diagnostic with a source excerpt:
    ///
    /// ```text
    /// error[MALM2304]: `@if` requires bool, found optional<int>
    ///   --> modules/lock-idle/outputs.kdl:18:23
    ///    |
    /// 18 |     @if "blur-size" {
    ///    |                       ^^^^^^^^^^^^^^^^^^^^^^^^
    ///
    ///   input declared here:
    ///   --> modules/lock-idle/inputs.kdl:7:5
    ///
    ///   help: use `@if-present` for optional values
    /// ```
    pub fn render(&self, sources: &SourceMap) -> String {
        let mut out = String::new();
        let kind = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let _ = writeln!(out, "{kind}[{}]: {}", self.code, self.message);
        if let Some(span) = self.span {
            render_span(&mut out, sources, span);
            let chain = sources.include_chain(span.file);
            if !chain.is_empty() {
                let rendered: Vec<String> = chain.iter().map(|p| p.display().to_string()).collect();
                let _ = writeln!(out, "  included via: {}", rendered.join(" -> "));
            }
        }
        for label in &self.labels {
            let _ = writeln!(out, "\n  {}:", label.message);
            render_span(&mut out, sources, label.span);
        }
        for note in &self.notes {
            let _ = writeln!(out, "  note: {note}");
        }
        if let Some(help) = &self.help {
            let _ = writeln!(out, "  help: {help}");
        }
        out
    }
}

fn render_span(out: &mut String, sources: &SourceMap, span: Span) {
    let (line, col) = sources.line_col(span.file, span.offset);
    let _ = writeln!(
        out,
        "  --> {}:{line}:{col}",
        sources.path(span.file).display()
    );
    if span.len == 0 && span.offset == 0 {
        return; // Synthetic spans have no source excerpt.
    }
    let text = sources.line_text(span.file, line);
    if text.is_empty() {
        return;
    }
    let gutter = line.to_string();
    let pad = " ".repeat(gutter.len());
    let _ = writeln!(out, "  {pad} |");
    let _ = writeln!(out, "  {gutter} | {text}");
    let underline_len = span.len.clamp(1, text.len().saturating_sub(col - 1).max(1));
    let _ = writeln!(
        out,
        "  {pad} | {}{}",
        " ".repeat(col.saturating_sub(1)),
        "^".repeat(underline_len)
    );
}

/// Diagnostics accumulated in reporting order during compilation.
#[derive(Debug, Default)]
pub struct Diagnostics {
    items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.items.push(diagnostic);
    }

    pub fn error(&mut self, code: &'static str, message: impl Into<String>) {
        self.push(Diagnostic::error(code, message));
    }

    /// Push an error carrying a primary span. Equivalent to
    /// `push(Diagnostic::error(code, message).with_span(span))`.
    pub fn error_at(&mut self, code: &'static str, message: impl Into<String>, span: Span) {
        self.push(Diagnostic::error(code, message).with_span(span));
    }

    /// Push an error carrying a primary span and help text. Equivalent to
    /// `push(Diagnostic::error(code, message).with_span(span).with_help(help))`.
    pub fn error_at_with_help(
        &mut self,
        code: &'static str,
        message: impl Into<String>,
        span: Span,
        help: impl Into<String>,
    ) {
        self.push(
            Diagnostic::error(code, message)
                .with_span(span)
                .with_help(help),
        );
    }

    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.severity == Severity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.items
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count()
    }

    /// Returns diagnostics in insertion order for structured host reporting.
    #[allow(dead_code)]
    pub fn items(&self) -> &[Diagnostic] {
        &self.items
    }

    /// Render diagnostics in insertion order.
    pub fn render(&self, sources: &SourceMap) -> String {
        let mut out = String::new();
        for item in &self.items {
            out.push_str(&item.render(sources));
            out.push('\n');
        }
        out
    }
}

// Error codes are stable API. Add new codes without renumbering existing ones.

/// MALM1xxx covers parse and node-shape errors.
#[allow(dead_code)] // The registry reserves and documents the complete code space.
pub mod codes {
    // Parse and shape (MALM1xxx)
    pub const PARSE: &str = "MALM1001";
    pub const UNKNOWN_NODE: &str = "MALM1002";
    pub const NODE_SHAPE: &str = "MALM1003";
    pub const DUPLICATE: &str = "MALM1004";
    pub const INCLUDE: &str = "MALM1005";
    pub const RESERVED_NAME: &str = "MALM1006";

    // Types and values (MALM2xxx)
    pub const TYPE_MISMATCH: &str = "MALM2001";
    pub const UNKNOWN_INPUT: &str = "MALM2002";
    pub const MISSING_REQUIRED: &str = "MALM2003";
    pub const BAD_DEFAULT: &str = "MALM2004";
    pub const RECORD_FIELD: &str = "MALM2005";
    pub const NULL_NOT_OPTIONAL: &str = "MALM2006";
    pub const UNKNOWN_TYPE: &str = "MALM2007";
    pub const TYPE_CYCLE: &str = "MALM2008";
    pub const TYPE_DEPTH: &str = "MALM2009";
    pub const TYPE_COMPLEXITY: &str = "MALM2010";
    pub const BAD_REF: &str = "MALM2101";
    pub const UNDEFINED_REF: &str = "MALM2102";
    pub const WHEN_PREDICATE: &str = "MALM2304";
    pub const CODEC: &str = "MALM2401";

    // Resolution (MALM3xxx)
    pub const UNKNOWN_MODULE: &str = "MALM3001";
    pub const UNKNOWN_PROFILE: &str = "MALM3002";
    pub const PROFILE_CYCLE: &str = "MALM3003";
    pub const ALIAS_CONFLICT: &str = "MALM3004";
    pub const SLOT: &str = "MALM3005";
    pub const SIBLING_CONFLICT: &str = "MALM3006";
    pub const PATCH: &str = "MALM3007";
    pub const FRAGMENT: &str = "MALM3008";
    pub const EXTEND_MODULE: &str = "MALM3009";
    pub const DEST_CONFLICT: &str = "MALM3010";

    // Expansion and budgets (MALM4xxx)
    pub const BUDGET: &str = "MALM4001";
    pub const LOOP_SOURCE: &str = "MALM4002";
    pub const BINDING: &str = "MALM4003";
    pub const RANGE: &str = "MALM4004";

    // Rendering and artifacts (MALM5xxx)
    pub const TEMPLATE: &str = "MALM5001";
    pub const EMIT: &str = "MALM5002";
    pub const KDL_GEN: &str = "MALM5003";
    pub const ARTIFACT_VALIDATE: &str = "MALM5004";
    pub const OUTPUT_PATH: &str = "MALM5005";

    // Doctor / requires (MALM6xxx)
    pub const REQUIREMENT: &str = "MALM6001";
}
