//! Policy finding kinds, severities, and user-facing records.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySeverity {
    Block,
    Notice,
}

#[derive(Debug, Clone)]
pub struct PolicyFinding {
    pub target: Option<PathBuf>,
    pub owner: String,
    pub category: PolicyFindingKind,
    pub severity: PolicySeverity,
    pub reason: &'static str,
    pub allow_flag: &'static str,
}

impl PolicyFinding {
    pub fn is_block(&self) -> bool {
        self.severity == PolicySeverity::Block
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyFindingKind {
    ShellStartupFile,
    OutsideHomeDir,
    ExternalSymlinkSource,
    InHomeSymlinkSource,
    UnverifiableSymlink,
    ExecutableInPath,
    AssetWithoutChecksum,
    SshFile,
    CredentialStore,
    AutostartEntry,
    SystemdUserUnit,
    SessionEnvironment,
    GitGlobalConfig,
    MalmInternalState,
    ExecCapableConfig,
    LocalInclude,
}

impl PolicyFindingKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ShellStartupFile => "shell startup file",
            Self::OutsideHomeDir => "write outside home directory",
            Self::ExternalSymlinkSource => "external symlink source",
            Self::InHomeSymlinkSource => "outside repo symlink source",
            Self::UnverifiableSymlink => "unverifiable symlink source",
            Self::ExecutableInPath => "executable in PATH",
            Self::AssetWithoutChecksum => "asset without SHA256",
            Self::SshFile => "SSH configuration",
            Self::CredentialStore => "credential store",
            Self::AutostartEntry => "autostart entry",
            Self::SystemdUserUnit => "systemd user unit",
            Self::SessionEnvironment => "session environment file",
            Self::GitGlobalConfig => "global git config",
            Self::MalmInternalState => "Malm internal state",
            Self::ExecCapableConfig => "exec-capable session config",
            Self::LocalInclude => "local configuration include",
        }
    }
}
