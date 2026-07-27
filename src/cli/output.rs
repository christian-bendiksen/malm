//! Presentation and error-vocabulary boundary for human and structured CLI output.

use std::io::{IsTerminal, Write as _};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use super::{ColorChoice, OutputFormat, OutputOptions};
use crate::{
    CommitError, DiagnosticEvent, DiagnosticSink, EngineError, EngineOperation, EnginePorts,
    PreparedStoreIssue, ProgressEvent, ProgressSink,
};

const MAX_ERROR_CHARS: usize = 8_192;

/// Formats into a human-readable buffer and appends one LF.
///
/// Callers pass `format_args!(...)`, retaining compile-time format checks without
/// introducing a formatting macro at each output site.
pub(super) fn out_line(out: &mut String, args: std::fmt::Arguments<'_>) {
    use std::fmt::Write as _;
    let _ = out.write_fmt(args);
    out.push('\n');
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Tone {
    Success,
    Attention,
    Neutral,
    Error,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Output {
    command: &'static str,
    options: OutputOptions,
    stdout_color: bool,
    stderr_color: bool,
    progress: bool,
}

#[derive(Serialize)]
struct SuccessEnvelope<'a> {
    schema_version: u32,
    command: &'a str,
    outcome: &'a str,
    data: Value,
    diagnostics: Vec<CliDiagnostic>,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    schema_version: u32,
    command: &'a str,
    outcome: &'static str,
    data: Option<Value>,
    diagnostics: Vec<CliDiagnostic>,
    error: CliError<'a>,
}

#[derive(Serialize)]
struct CliDiagnostic {
    severity: &'static str,
    code: String,
    message: String,
}

#[derive(Serialize)]
struct CliError<'a> {
    category: &'static str,
    code: &'a str,
    message: &'a str,
    help: Option<&'static str>,
}

impl Output {
    #[must_use]
    pub(super) fn new(command: &'static str, options: OutputOptions) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some()
            || std::env::var_os("TERM").is_some_and(|term| term == "dumb");
        let color = |terminal: bool| match options.color {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => terminal && !no_color,
        };
        Self {
            command,
            options,
            stdout_color: color(std::io::stdout().is_terminal()),
            stderr_color: color(std::io::stderr().is_terminal()),
            progress: !matches!(options.format, OutputFormat::Json)
                && std::io::stderr().is_terminal()
                && std::env::var_os("TERM").is_none_or(|term| term != "dumb"),
        }
    }

    #[must_use]
    pub(super) const fn is_json(self) -> bool {
        matches!(self.options.format, OutputFormat::Json)
    }

    #[must_use]
    pub(super) const fn verbose(self) -> bool {
        self.options.verbose > 0
    }

    #[must_use]
    pub(super) const fn command(self) -> &'static str {
        self.command
    }

    #[must_use]
    pub(super) fn heading(self, text: &str, tone: Tone) -> String {
        paint(text, tone, self.stdout_color)
    }

    pub(super) fn human(self, body: &str) -> Result<()> {
        debug_assert!(!self.is_json());
        write_stdout(body.as_bytes())
    }

    pub(super) fn prompt(self, prompt: &str) -> Result<()> {
        debug_assert!(!self.is_json());
        write_stderr(prompt.as_bytes())
    }

    pub(super) fn engine_ports(self, ports: EnginePorts) -> EnginePorts {
        if !self.progress {
            return ports;
        }
        ports.with_sinks(
            Arc::new(CliProgressSink::default()),
            Arc::new(CliDiagnosticSink),
        )
    }

    /// Emits one success result as JSON or human-readable text.
    ///
    /// Only the builder for the selected format runs, so the unselected
    /// representation is never constructed.
    pub(super) fn emit(
        self,
        outcome: &str,
        json: impl FnOnce() -> Value,
        human: impl FnOnce(&mut String),
    ) -> Result<()> {
        if self.is_json() {
            self.json(outcome, json())
        } else {
            let mut rendered = String::new();
            human(&mut rendered);
            self.human(&rendered)
        }
    }

    pub(super) fn json(self, outcome: &str, data: Value) -> Result<()> {
        debug_assert!(self.is_json());
        let envelope = SuccessEnvelope {
            schema_version: 1,
            command: self.command,
            outcome,
            data,
            diagnostics: Vec::new(),
        };
        write_json_stdout(&envelope)
    }

    pub(super) fn error(self, error: &anyhow::Error) -> Result<()> {
        let code = error_code(error);
        let message = bounded(error.to_string());
        let details = self.verbose().then(|| bounded(format!("{error:#}")));
        self.error_parts(code, &message, details.as_deref())
    }

    pub(super) fn invalid_request(self, message: &str) -> Result<()> {
        self.error_parts("invalid-request", &bounded(message.to_owned()), None)
    }

    pub(super) fn refusal(self, code: &'static str, message: &str) -> Result<()> {
        debug_assert!(self.is_json());
        self.error_parts(code, &bounded(message.to_owned()), None)
    }

    fn error_parts(self, code: &str, message: &str, details: Option<&str>) -> Result<()> {
        let help = error_help(code);
        if self.is_json() {
            let envelope = ErrorEnvelope {
                schema_version: 1,
                command: self.command,
                outcome: "error",
                data: None,
                diagnostics: Vec::new(),
                error: CliError {
                    category: error_category(code),
                    code,
                    message,
                    help,
                },
            };
            return write_json_stderr(&envelope);
        }

        let mut rendered = String::new();
        let label = paint(&format!("error[{code}]"), Tone::Error, self.stderr_color);
        out_line(&mut rendered, format_args!("{label}: {message}"));
        if let Some(help) = help {
            out_line(&mut rendered, format_args!("\n{help}"));
        }
        if let Some(details) = details.filter(|details| *details != message) {
            out_line(&mut rendered, format_args!("\nDetails\n  {details}"));
        }
        write_stderr(rendered.as_bytes())
    }
}

#[derive(Default)]
struct CliProgressSink {
    visible: Mutex<Vec<EngineOperation>>,
}

impl ProgressSink for CliProgressSink {
    fn emit(&self, event: ProgressEvent) {
        let Ok(mut visible) = self.visible.lock() else {
            return;
        };
        match event {
            ProgressEvent::OperationStarted { operation, .. } => {
                if progress_label(operation).is_some() {
                    visible.push(operation);
                }
            }
            ProgressEvent::OperationFinished { operation, .. } => {
                if let Some(index) = visible
                    .iter()
                    .rposition(|candidate| *candidate == operation)
                {
                    visible.remove(index);
                }
            }
            _ => return,
        }
        let bytes = visible
            .last()
            .and_then(|operation| progress_label(*operation))
            .map_or_else(
                || b"\r\x1b[2K".to_vec(),
                |label| format!("\r\x1b[2K{label}...").into_bytes(),
            );
        let _ = write_stderr(&bytes);
    }
}

struct CliDiagnosticSink;

impl DiagnosticSink for CliDiagnosticSink {
    fn emit(&self, _event: DiagnosticEvent<'_>) {}
}

const fn progress_label(operation: EngineOperation) -> Option<&'static str> {
    match operation {
        EngineOperation::CreateLockV1 => Some("Creating source lock"),
        EngineOperation::UpdateLockV1 => Some("Updating source lock"),
        EngineOperation::AcquireGraphV1 | EngineOperation::AcquireLocalGraphV1 => {
            Some("Acquiring source graph")
        }
        EngineOperation::PrepareStaticProfileV1 => Some("Evaluating profile"),
        EngineOperation::PrepareStaticDeploymentV1 => Some("Preparing deployment"),
        EngineOperation::PrepareTrackedRootV1 => Some("Preparing tracked deployment"),
        EngineOperation::UpdateTrackedRootV1 => Some("Refreshing tracked source"),
        EngineOperation::PrepareProfileSwitchV1 => Some("Preparing profile change"),
        EngineOperation::PrepareCheckoutV1 => Some("Preparing restoration"),
        EngineOperation::PrepareDisableV1
        | EngineOperation::PrepareEnableV1
        | EngineOperation::PrepareNamespaceRemovalV1
        | EngineOperation::PrepareRetentionAuthorityV1 => Some("Preparing namespace change"),
        EngineOperation::CommitV1 => Some("Applying plan"),
        EngineOperation::RecoverV1 => Some("Recovering transaction"),
        EngineOperation::FsckV1 => Some("Verifying store"),
        EngineOperation::PruneV1 => Some("Computing reachable objects"),
        _ => None,
    }
}

fn paint(text: &str, tone: Tone, enabled: bool) -> String {
    if !enabled {
        return text.to_owned();
    }
    let code = match tone {
        Tone::Success => "1;32",
        Tone::Attention => "1;33",
        Tone::Neutral => "1;36",
        Tone::Error => "1;31",
    };
    format!("\x1b[{code}m{text}\x1b[0m")
}

fn write_json_stdout(value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    write_stdout(&bytes)
}

fn write_json_stderr(value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    write_stderr(&bytes)
}

fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(bytes) {
        Ok(()) => stdout.flush().map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_stderr(bytes: &[u8]) -> Result<()> {
    let mut stderr = std::io::stderr().lock();
    match stderr.write_all(bytes) {
        Ok(()) => stderr.flush().map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn write_parser_stdout(rendered: &str) -> Result<()> {
    write_stdout(rendered.as_bytes())
}

pub(super) fn write_parser_stderr(rendered: &str) -> Result<()> {
    write_stderr(rendered.as_bytes())
}

pub(super) fn json_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn bounded(value: String) -> String {
    const TRUNCATION: &str = "... [truncated]";
    let character_count = value.chars().count();
    let limit = if character_count > MAX_ERROR_CHARS {
        MAX_ERROR_CHARS - TRUNCATION.chars().count()
    } else {
        MAX_ERROR_CHARS
    };
    let mut bounded = String::with_capacity(value.len().min(MAX_ERROR_CHARS));
    for character in value.chars().take(limit) {
        bounded.push(
            if character.is_control() && character != '\n' && character != '\t' {
                '?'
            } else {
                character
            },
        );
    }
    if character_count > MAX_ERROR_CHARS {
        bounded.push_str(TRUNCATION);
    }
    bounded
}

fn error_code(error: &anyhow::Error) -> &'static str {
    if let Some(error) = error.downcast_ref::<CommitError>() {
        return commit_error_code(error);
    }
    if let Some(error) = error.downcast_ref::<EngineError>() {
        return engine_error_code(error);
    }
    let message = error.to_string();
    if message.contains("no durable plan") {
        "plan-not-found"
    } else if message.contains("ambiguous plan short ID") {
        "ambiguous-plan"
    } else if message.contains("ambiguous") && message.contains("short ID") {
        "ambiguous-id"
    } else if message.starts_with("no ") && message.contains(" matches ") {
        "id-not-found"
    } else if message.contains("approval") && message.contains("match") {
        "approval-mismatch"
    } else if message.contains("recovery") && message.contains("required") {
        "recovery-required"
    } else if message.contains("stale") || message.contains("no longer matches") {
        "stale-plan"
    } else if message.contains("store is not ready") {
        "store-not-ready"
    } else if (message.contains("profile") && message.contains("required"))
        || (message.contains("default-profile") && message.contains("none requested"))
    {
        "profile-required"
    } else if message.contains("not explicitly granted") {
        "authority-denied"
    } else if message.contains("must be")
        || message.contains("requires")
        || message.contains("short ID")
        || message.contains("reference uses the wrong")
    {
        "invalid-request"
    } else {
        "command-failed"
    }
}

/// Groups [`CommitError`] variants for both CLI and machine/v1 error vocabularies.
///
/// `PlanInUse` and `InvalidPlanState` remain separate because the CLI assigns
/// `PlanInUse` its own code while machine/v1 combines the retained-state
/// conflicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommitErrorClass {
    ReadOnlyStore,
    Busy,
    MissingPlan,
    MissingArtifact,
    ApprovalMismatch,
    StaleNamespaceHead,
    RecoveryRequired,
    UnsafeTarget,
    CorruptStore,
    CorruptArtifact,
    PlanInUse,
    /// An `InvalidPlan` or `RollbackFailed` error.
    InvalidPlanState,
    Io,
    /// Any variant not named explicitly by either vocabulary.
    ///
    /// The CLI maps this class to `invalid-deployment` and `Conflict` for
    /// compatibility with [`CommitErrorClass::InvalidPlanState`]. Machine/v1
    /// maps it to `Internal` and `InternalEngineError` so unknown failures are
    /// not mislabeled as user conflicts. Preserve this distinction when
    /// extending [`CommitError`].
    Other,
}

pub(super) fn classify_commit_error(error: &CommitError) -> CommitErrorClass {
    match error {
        CommitError::ReadOnlyStore => CommitErrorClass::ReadOnlyStore,
        CommitError::Busy => CommitErrorClass::Busy,
        CommitError::MissingPlan(_) => CommitErrorClass::MissingPlan,
        CommitError::MissingArtifact(_) => CommitErrorClass::MissingArtifact,
        CommitError::ApprovalPlanMismatch | CommitError::ApprovalFindingsMismatch => {
            CommitErrorClass::ApprovalMismatch
        }
        CommitError::StaleNamespaceHead { .. } => CommitErrorClass::StaleNamespaceHead,
        CommitError::RecoveryRequired => CommitErrorClass::RecoveryRequired,
        CommitError::UnknownTargetAuthority(_)
        | CommitError::UnsafeTarget(_)
        | CommitError::StaleTarget(_)
        | CommitError::StaleInspection
        | CommitError::TargetOwnershipConflict { .. }
        | CommitError::UnownedTargetMutation { .. } => CommitErrorClass::UnsafeTarget,
        CommitError::InvalidStore(_) | CommitError::InvalidJournal(_) => {
            CommitErrorClass::CorruptStore
        }
        CommitError::CorruptArtifact { .. } => CommitErrorClass::CorruptArtifact,
        CommitError::PlanInUse(_) => CommitErrorClass::PlanInUse,
        CommitError::InvalidPlan(_) | CommitError::RollbackFailed(_) => {
            CommitErrorClass::InvalidPlanState
        }
        CommitError::Io { .. } => CommitErrorClass::Io,
        _ => CommitErrorClass::Other,
    }
}

/// Groups [`EngineError`] variants shared by the CLI and machine/v1 adapters.
///
/// `Commit` carries its nested class so both adapters can reuse commit mappings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EngineErrorClass {
    ReadOnlyStore,
    PreparedMissingPlan,
    PreparedMissingArtifact,
    PreparedBusy,
    PreparedStaleHead,
    PreparedUnsafeTarget,
    /// Any prepared-store issue not classified above.
    PreparedInvalid,
    Commit(CommitErrorClass),
    Io,
    /// Any variant not named explicitly by either vocabulary.
    Other,
}

pub(super) fn classify_engine_error(error: &EngineError) -> EngineErrorClass {
    match error {
        EngineError::ReadOnlyStore => EngineErrorClass::ReadOnlyStore,
        EngineError::PreparedStore { reason, .. } => match reason {
            PreparedStoreIssue::MissingPlan => EngineErrorClass::PreparedMissingPlan,
            PreparedStoreIssue::MissingBlob | PreparedStoreIssue::UnknownArtifact(_) => {
                EngineErrorClass::PreparedMissingArtifact
            }
            PreparedStoreIssue::PublicationBusy => EngineErrorClass::PreparedBusy,
            PreparedStoreIssue::StaleNamespaceHead { .. } => EngineErrorClass::PreparedStaleHead,
            PreparedStoreIssue::UnsafeTarget { .. }
            | PreparedStoreIssue::UnknownTargetAuthority(_)
            | PreparedStoreIssue::TargetOwnershipConflict { .. }
            | PreparedStoreIssue::UnownedTargetMutation { .. } => {
                EngineErrorClass::PreparedUnsafeTarget
            }
            _ => EngineErrorClass::PreparedInvalid,
        },
        EngineError::Commit { source } => EngineErrorClass::Commit(classify_commit_error(source)),
        EngineError::Io { .. } => EngineErrorClass::Io,
        _ => EngineErrorClass::Other,
    }
}

fn commit_error_code(error: &CommitError) -> &'static str {
    commit_class_code(classify_commit_error(error))
}

const fn commit_class_code(class: CommitErrorClass) -> &'static str {
    match class {
        CommitErrorClass::ReadOnlyStore => "read-only-store",
        CommitErrorClass::Busy => "operation-busy",
        CommitErrorClass::MissingPlan => "plan-not-found",
        CommitErrorClass::MissingArtifact => "artifact-not-found",
        CommitErrorClass::ApprovalMismatch => "approval-mismatch",
        CommitErrorClass::StaleNamespaceHead => "stale-plan",
        CommitErrorClass::RecoveryRequired => "recovery-required",
        CommitErrorClass::UnsafeTarget => "unsafe-target",
        CommitErrorClass::CorruptStore => "corrupt-store",
        CommitErrorClass::CorruptArtifact => "corrupt-artifact",
        CommitErrorClass::PlanInUse => "plan-in-use",
        CommitErrorClass::Io => "deployment-io",
        CommitErrorClass::InvalidPlanState => "invalid-deployment",
        // Other shares this CLI code but remains distinct because machine/v1
        // maps it to an internal error.
        CommitErrorClass::Other => "invalid-deployment",
    }
}

fn engine_error_code(error: &EngineError) -> &'static str {
    match classify_engine_error(error) {
        EngineErrorClass::ReadOnlyStore => "read-only-store",
        EngineErrorClass::PreparedMissingPlan => "plan-not-found",
        EngineErrorClass::PreparedMissingArtifact => "artifact-not-found",
        EngineErrorClass::PreparedBusy => "operation-busy",
        EngineErrorClass::PreparedStaleHead => "stale-plan",
        EngineErrorClass::PreparedUnsafeTarget => "unsafe-target",
        EngineErrorClass::Commit(class) => commit_class_code(class),
        EngineErrorClass::Io => "deployment-io",
        EngineErrorClass::PreparedInvalid | EngineErrorClass::Other => "invalid-deployment",
    }
}

fn error_category(code: &str) -> &'static str {
    match code {
        "plan-not-found" | "id-not-found" => "not_found",
        "artifact-not-found" | "state-parent-missing" => "not_found",
        "authority-denied" | "read-only-store" => "permission_denied",
        "unsupported-store-version" => "unsupported",
        "profile-required" | "invalid-request" | "ambiguous-plan" | "ambiguous-id" => {
            "invalid_request"
        }
        "approval-mismatch"
        | "approval-required"
        | "confirmation-required"
        | "recovery-required"
        | "stale-plan"
        | "store-not-ready"
        | "unsafe-directory"
        | "unsafe-target"
        | "store-changed"
        | "corrupt-store"
        | "corrupt-artifact"
        | "plan-in-use"
        | "operation-busy"
        | "invalid-deployment" => "conflict",
        "internal" => "internal",
        _ => "unavailable",
    }
}
fn error_help(code: &str) -> Option<&'static str> {
    match code {
        "plan-not-found" => Some("List available plans with `malm plan list`."),
        "ambiguous-plan" => Some("Use a longer `plan:<hex>` ID from `malm plan list`."),
        "ambiguous-id" => Some("Use a longer typed short ID."),
        "recovery-required" => {
            Some("Recover the interrupted transaction with `malm store recover`.")
        }
        "stale-plan" => Some("Create and review a fresh plan before applying."),
        "store-not-ready" => Some("Initialize the store with `malm store init`."),
        "plan-in-use" => Some("The plan is retained by namespace history or an explicit pin."),
        "profile-required" => {
            Some("Pass `--profile NAME` or declare a default profile in the source.")
        }
        "approval-required" => Some("Review the durable plan and apply it explicitly."),
        "confirmation-required" => Some("Pass `--yes` or apply the durable plan explicitly."),
        _ => None,
    }
}

#[cfg(test)]
mod classifier_tests {
    use std::path::PathBuf;

    use super::{CommitErrorClass, commit_class_code, commit_error_code, engine_error_code};
    use crate::{CommitError, EngineError, OwnershipOverlapKindV1, PreparedStoreIssue};
    use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName, PreparedId};

    fn digest() -> Digest {
        Digest::new(format!("sha256-{}", "1".repeat(64))).unwrap()
    }

    fn plan_id() -> PreparedId {
        PreparedId::new(format!("pp-{}", "2".repeat(64))).unwrap()
    }

    fn namespace() -> NamespaceName {
        NamespaceName::new("default".to_owned()).unwrap()
    }

    fn authority() -> DeploymentName {
        DeploymentName::new("home".to_owned()).unwrap()
    }

    /// Pairs one representative of each [`CommitError`] variant with its
    /// pre-classifier code.
    fn commit_error_cases() -> Vec<(CommitError, &'static str)> {
        vec![
            (CommitError::ReadOnlyStore, "read-only-store"),
            (CommitError::Busy, "operation-busy"),
            (
                CommitError::InvalidStore("reason".to_owned()),
                "corrupt-store",
            ),
            (CommitError::MissingPlan(plan_id()), "plan-not-found"),
            (CommitError::PlanInUse(plan_id()), "plan-in-use"),
            (
                CommitError::InvalidPlan("reason".to_owned()),
                "invalid-deployment",
            ),
            (CommitError::ApprovalPlanMismatch, "approval-mismatch"),
            (CommitError::ApprovalFindingsMismatch, "approval-mismatch"),
            (
                CommitError::StaleNamespaceHead {
                    namespace: namespace(),
                    expected: None,
                    actual: Some(digest()),
                },
                "stale-plan",
            ),
            (
                CommitError::TargetOwnershipConflict {
                    requesting_namespace: namespace(),
                    owning_namespace: namespace(),
                    requesting_authority: Box::new(authority()),
                    owning_authority: Box::new(authority()),
                    requested_path: ".config/a".to_owned(),
                    owned_path: ".config/a".to_owned(),
                    overlap: OwnershipOverlapKindV1::Exact,
                },
                "unsafe-target",
            ),
            (
                CommitError::UnownedTargetMutation {
                    namespace: namespace(),
                    authority: authority(),
                    relative_path: ".config/a".to_owned(),
                },
                "unsafe-target",
            ),
            (CommitError::MissingArtifact(digest()), "artifact-not-found"),
            (
                CommitError::CorruptArtifact {
                    expected: digest(),
                    actual: digest(),
                },
                "corrupt-artifact",
            ),
            (
                CommitError::UnknownTargetAuthority(authority()),
                "unsafe-target",
            ),
            (
                CommitError::UnsafeTarget("reason".to_owned()),
                "unsafe-target",
            ),
            (
                CommitError::StaleTarget("reason".to_owned()),
                "unsafe-target",
            ),
            (CommitError::StaleInspection, "unsafe-target"),
            (
                CommitError::RollbackFailed("reason".to_owned()),
                "invalid-deployment",
            ),
            (CommitError::RecoveryRequired, "recovery-required"),
            (
                CommitError::InvalidJournal("reason".to_owned()),
                "corrupt-store",
            ),
            (
                CommitError::Io {
                    operation: "open",
                    path: PathBuf::from("/store"),
                    source: std::io::Error::other("io"),
                },
                "deployment-io",
            ),
        ]
    }

    /// Pairs each classified [`PreparedStoreIssue`] group and remaining
    /// top-level [`EngineError`] group with its pre-classifier code.
    fn engine_error_cases() -> Vec<(EngineError, &'static str)> {
        let prepared = |reason| EngineError::PreparedStore {
            path: PathBuf::from("/store"),
            reason,
        };
        vec![
            (EngineError::ReadOnlyStore, "read-only-store"),
            (prepared(PreparedStoreIssue::MissingPlan), "plan-not-found"),
            (
                prepared(PreparedStoreIssue::MissingBlob),
                "artifact-not-found",
            ),
            (
                prepared(PreparedStoreIssue::UnknownArtifact(
                    ArtifactId::new("artifact".to_owned()).unwrap(),
                )),
                "artifact-not-found",
            ),
            (
                prepared(PreparedStoreIssue::PublicationBusy),
                "operation-busy",
            ),
            (
                prepared(PreparedStoreIssue::StaleNamespaceHead {
                    namespace: namespace(),
                    expected: None,
                    actual: Some(digest()),
                }),
                "stale-plan",
            ),
            (
                prepared(PreparedStoreIssue::UnsafeTarget {
                    detail: "reason".to_owned(),
                }),
                "unsafe-target",
            ),
            (
                prepared(PreparedStoreIssue::UnknownTargetAuthority(authority())),
                "unsafe-target",
            ),
            (
                prepared(PreparedStoreIssue::UnownedTargetMutation {
                    namespace: namespace(),
                    authority: authority(),
                    relative_path: ".config/a".to_owned(),
                }),
                "unsafe-target",
            ),
            (
                prepared(PreparedStoreIssue::ObservationChanged),
                "invalid-deployment",
            ),
            (
                EngineError::Commit {
                    source: CommitError::PlanInUse(plan_id()),
                },
                "plan-in-use",
            ),
            (
                EngineError::Commit {
                    source: CommitError::RollbackFailed("reason".to_owned()),
                },
                "invalid-deployment",
            ),
            (
                EngineError::Io {
                    operation: "open",
                    path: PathBuf::from("/store"),
                    source: std::io::Error::other("io"),
                },
                "deployment-io",
            ),
        ]
    }

    #[test]
    fn every_commit_error_variant_keeps_its_pre_classifier_code() {
        for (error, expected) in commit_error_cases() {
            assert_eq!(commit_error_code(&error), expected, "{error:?}");
        }
    }

    #[test]
    fn every_engine_error_group_keeps_its_pre_classifier_code() {
        for (error, expected) in engine_error_cases() {
            assert_eq!(engine_error_code(&error), expected, "{error:?}");
        }
    }

    #[test]
    fn other_commit_error_class_keeps_user_visible_invalid_deployment_code() {
        // Human and JSON output retain the historical invalid-deployment code
        // for unclassified commit errors; machine/v1 classifies them as internal.
        assert_eq!(
            commit_class_code(CommitErrorClass::Other),
            "invalid-deployment"
        );
    }
}
