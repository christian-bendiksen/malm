//! Classifies lexical and resolved destinations against home, Malm state,
//! PATH, and sensitive path rules.

use crate::paths::normalize_lexical;
use crate::policy::advisory::{
    DestinationFinding, is_shell_startup_file, is_user_path_target, sensitive_home_category,
};
use crate::policy::model::{PolicyFinding, PolicyFindingKind, PolicySeverity};
use crate::policy::overrides::RemotePolicyOverrides;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DestinationKind {
    Symlink,
    Asset,
}

pub(super) struct DestinationPolicyContext<'a> {
    pub home: &'a Path,
    pub home_canonical: PathBuf,
    pub path_dirs: Vec<PathBuf>,
    pub malm_dirs: Vec<PathBuf>,
    pub allow: RemotePolicyOverrides,
}

impl DestinationPolicyContext<'_> {
    // Classify both the spelled path and its physical resolution: a
    // symlinked parent can silently redirect an inside-home path outside it.
    pub(super) fn push_destination_findings(
        &self,
        raw: &Path,
        label: &str,
        kind: DestinationKind,
        violations: &mut Vec<PolicyFinding>,
    ) {
        let norm = normalize_lexical(raw);
        let physical = resolve_destination_physically(&norm);

        let mut consider: Vec<&Path> = vec![norm.as_path()];
        if let Some(p) = physical.as_deref()
            && p != norm.as_path()
        {
            consider.push(p);
        }

        let mut seen: Vec<PolicyFindingKind> = Vec::new();
        for path in consider {
            for (category, severity, reason, flag) in self.classify_destination(path, kind) {
                if seen.contains(&category) {
                    continue;
                }
                if severity == PolicySeverity::Block && self.override_allows_destination(category) {
                    continue;
                }
                seen.push(category);
                violations.push(PolicyFinding {
                    target: Some(raw.to_path_buf()),
                    owner: label.to_owned(),
                    category,
                    severity,
                    reason,
                    allow_flag: flag,
                });
            }
        }
    }

    fn classify_destination(&self, path: &Path, kind: DestinationKind) -> Vec<DestinationFinding> {
        let mut out = Vec::new();

        if kind == DestinationKind::Symlink && is_shell_startup_file(path) {
            out.push((
                PolicyFindingKind::ShellStartupFile,
                PolicySeverity::Notice,
                "shell startup files run commands on every shell start",
                "",
            ));
        }

        if self.malm_dirs.iter().any(|d| path.starts_with(d)) {
            out.push((
                PolicyFindingKind::MalmInternalState,
                PolicySeverity::Block,
                "destination is inside Malm's own state/config directory",
                "",
            ));
        }

        if !path.starts_with(self.home) && !path.starts_with(&self.home_canonical) {
            out.push((
                PolicyFindingKind::OutsideHomeDir,
                PolicySeverity::Block,
                "destination is outside the user home directory",
                "--allow-outside-home",
            ));
        }

        let in_path_dir = match kind {
            DestinationKind::Asset => self.path_dirs.iter().any(|dir| path.starts_with(dir)),
            DestinationKind::Symlink => is_user_path_target(path, &self.path_dirs),
        };
        if in_path_dir {
            out.push((
                PolicyFindingKind::ExecutableInPath,
                PolicySeverity::Notice,
                "installs a command into a user PATH directory",
                "",
            ));
        }

        if let Some(found) = sensitive_home_category(path, self.home) {
            out.push(found);
        }

        out
    }

    // External-source, unverifiable, and asset findings are gated by their own
    // collectors rather than per destination.
    fn override_allows_destination(&self, category: PolicyFindingKind) -> bool {
        match category {
            PolicyFindingKind::OutsideHomeDir => self.allow.outside_home,
            PolicyFindingKind::SshFile | PolicyFindingKind::CredentialStore => self.allow.secrets,
            PolicyFindingKind::ExternalSymlinkSource
            | PolicyFindingKind::UnverifiableSymlink
            | PolicyFindingKind::AssetWithoutChecksum => true,
            _ => false,
        }
    }
}

// Canonicalize the deepest existing ancestor, then re-append the
// not-yet-existing tail; the leaf itself is deliberately not followed.
pub(crate) fn resolve_destination_physically(norm: &Path) -> Option<PathBuf> {
    let file_name = norm.file_name()?;
    let parent = norm.parent().unwrap_or_else(|| Path::new("/"));

    let mut cursor = parent;
    loop {
        match cursor.canonicalize() {
            Ok(real) => {
                let tail = parent.strip_prefix(cursor).ok()?;
                return Some(normalize_lexical(&real.join(tail).join(file_name)));
            }
            Err(_) => cursor = cursor.parent()?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::overrides::RemotePolicyOverrides;

    fn ctx(home: &Path) -> DestinationPolicyContext<'_> {
        DestinationPolicyContext {
            home,
            home_canonical: home.to_path_buf(),
            path_dirs: Vec::new(),
            malm_dirs: Vec::new(),
            allow: RemotePolicyOverrides::default(),
        }
    }

    fn categories(findings: &[DestinationFinding]) -> Vec<PolicyFindingKind> {
        findings.iter().map(|f| f.0).collect()
    }

    #[test]
    fn destination_outside_home_is_blocked() {
        // A `to=` path from an untrusted remote config must be blocked if it
        // escapes home, whether spelled as `~/../etc/...` or an absolute path.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let policy = ctx(home);

        let outside = Path::new("/etc/malm-evil");
        let cats = categories(&policy.classify_destination(outside, DestinationKind::Symlink));
        assert!(
            cats.contains(&PolicyFindingKind::OutsideHomeDir),
            "an absolute out-of-home destination must be flagged OutsideHomeDir, got {cats:?}"
        );

        // A `~/../escape` style path normalises to outside home too.
        let normalized = normalize_lexical(&home.join("../escape-marker"));
        let cats = categories(&policy.classify_destination(&normalized, DestinationKind::Symlink));
        assert!(
            cats.contains(&PolicyFindingKind::OutsideHomeDir),
            "`~/../escape` must resolve outside home and be flagged, got {cats:?}"
        );
    }

    #[test]
    fn destination_inside_home_is_not_blocked_for_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let policy = ctx(home);

        let inside = home.join(".config").join("app").join("config.toml");
        let cats = categories(&policy.classify_destination(&inside, DestinationKind::Symlink));
        assert!(
            !cats.contains(&PolicyFindingKind::OutsideHomeDir),
            "an in-home destination must not be flagged as escaping, got {cats:?}"
        );
    }

    #[test]
    fn destination_inside_malm_state_is_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let malm_dir = home.join(".local/share/malm");
        let mut policy = ctx(home);
        policy.malm_dirs = vec![malm_dir.clone()];

        let cats = categories(
            &policy.classify_destination(&malm_dir.join("evil"), DestinationKind::Asset),
        );
        assert!(
            cats.contains(&PolicyFindingKind::MalmInternalState),
            "a destination inside Malm's own state must be Blocked, got {cats:?}"
        );
    }
}
