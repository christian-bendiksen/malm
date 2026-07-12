//! Classifies sensitive home-relative destinations and discovers PATH entries.

use crate::paths::{home_dir_canonical, strip_home_prefix};
use crate::policy::model::{PolicyFindingKind, PolicySeverity};
use std::path::{Path, PathBuf};

pub(super) type DestinationFinding = (
    PolicyFindingKind,
    PolicySeverity,
    &'static str,
    &'static str,
);

// Severity encodes the threat model: paths that grant code execution or
// credential access block; merely-influential paths notice.
pub(super) fn sensitive_home_category(norm: &Path, _home: &Path) -> Option<DestinationFinding> {
    use PolicySeverity::{Block, Notice};
    let rel = strip_home_prefix(norm)?;
    let comps: Vec<&str> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    match comps.as_slice() {
        [".ssh", ..] => Some((
            PolicyFindingKind::SshFile,
            Block,
            "writes SSH configuration, which can grant remote account access",
            "--allow-secrets",
        )),
        [".gnupg", ..] | [".password-store", ..] => Some((
            PolicyFindingKind::CredentialStore,
            Block,
            "writes into a credential store",
            "--allow-secrets",
        )),
        [".config", "autostart", ..] => Some((
            PolicyFindingKind::AutostartEntry,
            Notice,
            "installs an autostart entry that runs at login",
            "",
        )),
        [".config", "systemd", "user", ..] => Some((
            PolicyFindingKind::SystemdUserUnit,
            Notice,
            "installs a systemd user unit that can execute commands",
            "",
        )),
        [".config", "environment.d", ..] | [".pam_environment"] => Some((
            PolicyFindingKind::SessionEnvironment,
            Notice,
            "sets session environment variables that affect every process",
            "",
        )),
        [".gitconfig"] | [".config", "git", ..] => Some((
            PolicyFindingKind::GitGlobalConfig,
            Notice,
            "writes the global git config, which can define command aliases",
            "",
        )),
        [".config", "hypr", "hyprland.conf"]
        | [".config", "hypr", "hyprland.lua"]
        | [".config", "hypr", "conf", ..]
        | [".config", "sway", "config"]
        | [".config", "sway", "config.d", ..]
        | [".config", "niri", "config.kdl"]
        | [".config", "mango", ..] => Some((
            PolicyFindingKind::ExecCapableConfig,
            Notice,
            "manages compositor/session configuration that can execute commands",
            "",
        )),
        [".config", "nushell", "config.nu"]
        | [".config", "nushell", "env.nu"]
        | [".config", "powershell", "Microsoft.PowerShell_profile.ps1"] => Some((
            PolicyFindingKind::ShellStartupFile,
            Notice,
            "shell startup files run commands on every shell start",
            "",
        )),
        [".config", "fish", "config.fish"]
        | [".config", "fish", "conf.d", ..]
        | [".config", "fish", "functions", ..] => Some((
            PolicyFindingKind::ShellStartupFile,
            Notice,
            "fish startup/function files run commands on every shell start",
            "",
        )),
        _ => None,
    }
}

// Only PATH entries inside home count. Reporting system directories would add
// noise, and configs cannot write them under normal permissions.
pub(crate) fn user_path_dirs(home: &Path) -> Vec<PathBuf> {
    let home_canonical = home_dir_canonical();
    let mut dirs = vec![home.join(".local/bin"), home.join("bin")];
    if let Ok(path) = std::env::var("PATH") {
        dirs.extend(
            path.split(':')
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.starts_with(home) || p.starts_with(&home_canonical)),
        );
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

pub(super) fn is_user_path_target(dst: &Path, path_dirs: &[PathBuf]) -> bool {
    path_dirs
        .iter()
        .any(|dir| dst.parent() == Some(dir.as_path()))
}

pub(super) fn is_shell_startup_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if matches!(
        name,
        ".bashrc"
            | ".bash_profile"
            | ".bash_login"
            | ".bash_logout"
            | ".zshrc"
            | ".zprofile"
            | ".zlogin"
            | ".zlogout"
            | ".zshenv"
            | ".profile"
            | ".kshrc"
            | ".cshrc"
            | ".tcshrc"
            | ".fishrc"
    ) {
        return true;
    }
    let s = path.to_string_lossy();
    s.contains(".config/fish/config.fish") || s.contains(".config/fish/conf.d/")
}
