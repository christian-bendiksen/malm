use std::fmt;
use std::fs::File;
use std::io;
use std::sync::Arc;

use malm_config::{
    TransformFailureV1, TransformIdentityV1, TransformRequestV1, TransformResponseV1,
};
use malm_format_component_api::FormatComponentAuthorizationV1;
use rustix::process::{Resource, getrlimit};

use crate::events::{DiagnosticSink, NoopDiagnosticSink, NoopProgressSink, ProgressSink};
use crate::{GitAcquisitionConfig, GitAcquisitionIssue, GitObjectFormat};

/// One logical file returned by an exact-Git host adapter.
///
/// Paths are intentionally raw at this boundary. Engine validates every path,
/// tree constraint, manifest, and digest before publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPackFile {
    path: String,
    bytes: Vec<u8>,
    mode: u32,
}

impl GitPackFile {
    /// Creates a non-executable committed regular file.
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: bytes.into(),
            mode: 0o644,
        }
    }

    /// Creates a committed regular file with an exact normalized Git mode.
    pub fn with_mode(
        path: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
        mode: u32,
    ) -> Result<Self, GitPackFileModeError> {
        if !matches!(mode, 0o644 | 0o755) {
            return Err(GitPackFileModeError { mode });
        }
        Ok(Self {
            path: path.into(),
            bytes: bytes.into(),
            mode,
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the normalized permission-only Git mode (`0644` or `0755`).
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    #[must_use]
    pub fn into_parts(self) -> (String, Vec<u8>) {
        (self.path, self.bytes)
    }

    /// Consumes the file into its path, exact bytes, and normalized mode.
    #[must_use]
    pub fn into_mode_parts(self) -> (String, Vec<u8>, u32) {
        (self.path, self.bytes, self.mode)
    }
}

/// A custom exact-Git adapter supplied a mode outside Git's regular-file set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Git pack file mode must be 0644 or 0755, got {mode:04o}")]
pub struct GitPackFileModeError {
    mode: u32,
}

impl GitPackFileModeError {
    #[must_use]
    pub const fn mode(self) -> u32 {
        self.mode
    }
}

/// Caller-supplied process facts frozen when an Engine is constructed.
///
/// `EnginePorts::system` samples these from the constructing process. Custom
/// embedders are trusted to supply facts that describe their security context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessFacts {
    effective_user_id: u32,
    open_file_soft_limit: Option<u64>,
}

impl ProcessFacts {
    #[must_use]
    pub const fn new(effective_user_id: u32, open_file_soft_limit: Option<u64>) -> Self {
        Self {
            effective_user_id,
            open_file_soft_limit,
        }
    }

    #[must_use]
    pub const fn effective_user_id(self) -> u32 {
        self.effective_user_id
    }

    #[must_use]
    pub const fn open_file_soft_limit(self) -> Option<u64> {
        self.open_file_soft_limit
    }
}

/// Supplies cryptographically secure bytes without granting path authority.
pub trait SecureRandomPort: Send + Sync + 'static {
    fn fill(&self, output: &mut [u8]) -> io::Result<()>;
}

/// Runs only the three bounded exact-Git stages required by acquisition.
///
/// This is a trusted provenance capability: implementations must initialize
/// the provided scratch repository, fetch only the requested URL and object,
/// and return that committed object's selected subtree. Engine validates all
/// returned data but cannot independently prove that a custom implementation
/// obtained it from the requested source. Capability panics are not isolated;
/// implementations must report operational failures as `GitAcquisitionIssue`.
pub trait GitProcessPort: Send + Sync + 'static {
    /// Resolves one canonical symbolic selector to one full tagged commit ID.
    ///
    /// The default is deterministic and unavailable so existing custom exact-Git
    /// adapters do not silently gain moving-reference authority.
    fn resolve_revision(
        &self,
        _config: &GitAcquisitionConfig,
        _url: &str,
        _selector: &str,
        _output_limit: u64,
    ) -> Result<String, GitAcquisitionIssue> {
        Err(GitAcquisitionIssue::SelectorResolutionUnavailable)
    }

    fn initialize(
        &self,
        config: &GitAcquisitionConfig,
        scratch: &File,
        object_format: GitObjectFormat,
        output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue>;

    fn fetch(
        &self,
        config: &GitAcquisitionConfig,
        scratch: &File,
        url: &str,
        object_id: &str,
        output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue>;

    /// Reads the selected committed subtree without checkout transformations.
    ///
    /// A regular `malm.lock` at the selected root is returned so tracked prepare
    /// can verify it; Engine removes lock and other reserved paths before pack
    /// content hashing. Existing exact-pack adapters may continue omitting it.
    fn read_pack(
        &self,
        config: &GitAcquisitionConfig,
        scratch: &File,
        object_format: GitObjectFormat,
        object_id: &str,
        subdir: &str,
    ) -> Result<Vec<GitPackFile>, GitAcquisitionIssue>;
}

/// Operational failure from the isolated format-component execution adapter.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{reason}")]
pub struct FormatComponentExecutionIssue {
    reason: String,
}

impl FormatComponentExecutionIssue {
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Executes one exact authorized component without granting Engine a runtime dependency.
pub trait FormatComponentExecutionPort: Send + Sync + 'static {
    fn invoke(
        &self,
        authorization: &FormatComponentAuthorizationV1,
        identity: &TransformIdentityV1,
        component_bytes: &[u8],
        request: &TransformRequestV1,
    ) -> Result<Result<TransformResponseV1, TransformFailureV1>, FormatComponentExecutionIssue>;
}

/// Explicit host capabilities and observers for one Engine.
#[derive(Clone)]
pub struct EnginePorts {
    process_facts: ProcessFacts,
    secure_random: Arc<dyn SecureRandomPort>,
    git_process: Arc<dyn GitProcessPort>,
    format_component_execution: Arc<dyn FormatComponentExecutionPort>,
    progress: Arc<dyn ProgressSink>,
    diagnostics: Arc<dyn DiagnosticSink>,
}

impl EnginePorts {
    #[must_use]
    pub fn new(
        process_facts: ProcessFacts,
        secure_random: Arc<dyn SecureRandomPort>,
        git_process: Arc<dyn GitProcessPort>,
        progress: Arc<dyn ProgressSink>,
        diagnostics: Arc<dyn DiagnosticSink>,
    ) -> Self {
        Self {
            process_facts,
            secure_random,
            git_process,
            format_component_execution: Arc::new(UnavailableFormatComponentExecutionPort),
            progress,
            diagnostics,
        }
    }

    /// Builds explicit adapters for the current process and hardened Git runner.
    #[must_use]
    pub fn system() -> Self {
        Self::new(
            ProcessFacts::new(
                rustix::process::geteuid().as_raw(),
                getrlimit(Resource::Nofile).current,
            ),
            Arc::new(SystemSecureRandomPort),
            Arc::new(SystemGitProcessPort),
            Arc::new(NoopProgressSink),
            Arc::new(NoopDiagnosticSink),
        )
    }

    /// Replaces observers while retaining the selected host capabilities.
    #[must_use]
    pub fn with_sinks(
        mut self,
        progress: Arc<dyn ProgressSink>,
        diagnostics: Arc<dyn DiagnosticSink>,
    ) -> Self {
        self.progress = progress;
        self.diagnostics = diagnostics;
        self
    }

    /// Installs the prepare-only pure-component execution adapter.
    #[must_use]
    pub fn with_format_component_execution(
        mut self,
        execution: Arc<dyn FormatComponentExecutionPort>,
    ) -> Self {
        self.format_component_execution = execution;
        self
    }

    #[must_use]
    pub const fn process_facts(&self) -> ProcessFacts {
        self.process_facts
    }

    pub(crate) fn secure_random(&self) -> &dyn SecureRandomPort {
        self.secure_random.as_ref()
    }

    pub(crate) fn git_process(&self) -> &dyn GitProcessPort {
        self.git_process.as_ref()
    }

    pub(crate) fn format_component_execution(&self) -> &dyn FormatComponentExecutionPort {
        self.format_component_execution.as_ref()
    }

    pub(crate) fn progress(&self) -> &dyn ProgressSink {
        self.progress.as_ref()
    }

    pub(crate) fn diagnostics(&self) -> &dyn DiagnosticSink {
        self.diagnostics.as_ref()
    }
}

impl fmt::Debug for EnginePorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnginePorts")
            .field("process_facts", &self.process_facts)
            .field("secure_random", &"dyn SecureRandomPort")
            .field("git_process", &"dyn GitProcessPort")
            .field(
                "format_component_execution",
                &"dyn FormatComponentExecutionPort",
            )
            .field("progress", &"dyn ProgressSink")
            .field("diagnostics", &"dyn DiagnosticSink")
            .finish()
    }
}

#[derive(Debug)]
struct SystemSecureRandomPort;

#[derive(Debug)]
struct UnavailableFormatComponentExecutionPort;

impl FormatComponentExecutionPort for UnavailableFormatComponentExecutionPort {
    fn invoke(
        &self,
        _authorization: &FormatComponentAuthorizationV1,
        _identity: &TransformIdentityV1,
        _component_bytes: &[u8],
        _request: &TransformRequestV1,
    ) -> Result<Result<TransformResponseV1, TransformFailureV1>, FormatComponentExecutionIssue>
    {
        Err(FormatComponentExecutionIssue::new(
            "no format-component execution adapter was configured",
        ))
    }
}

impl SecureRandomPort for SystemSecureRandomPort {
    fn fill(&self, output: &mut [u8]) -> io::Result<()> {
        getrandom::fill(output).map_err(io::Error::other)
    }
}

#[derive(Debug)]
pub(crate) struct SystemGitProcessPort;
