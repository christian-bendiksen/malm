//! Resolves a source-less local command from `--repo`, the active deployment,
//! the current directory, or the default state's repo.

use crate::app::context::GlobalCtx;
use crate::config::loader::local_config_candidate;
use crate::config::{LoadedConfigSource, load_local_config, load_snapshot_config};
use crate::paths::xdg_state_home;
use crate::source::SourceKind;
use crate::source::store::SourceSnapshot;
use crate::state::record::live_deployment_id_strict;
use crate::state::tracking::TrackedRemote;
use crate::state::transaction::{TransactionManifest, TransactionStore, transaction_alias};
use anyhow::Result;
use std::path::{Path, PathBuf};

pub(crate) enum LocalSource {
    Explicit,
    Active(String),
    CwdConfig,
    DefaultStateRepo(String),
}

// Precedence: --repo > active deployment > ./malm.kdl > default
// state's repo. Never silently adopt a remote-tracking default.
pub(crate) fn classify_local_source(ctx: &GlobalCtx) -> Result<LocalSource> {
    if ctx.repo.is_some() {
        return Ok(LocalSource::Explicit);
    }
    if let Some(id) = live_deployment_id_strict(ctx.state_namespace.as_str())? {
        return Ok(LocalSource::Active(id));
    }
    if local_config_candidate(ctx).is_some() {
        return Ok(LocalSource::CwdConfig);
    }
    if ctx.state_namespace.as_str() != "default"
        && let Some(id) = live_deployment_id_strict("default")?
    {
        let manifest = TransactionStore::new().read(&id)?;
        let remote = matches!(
            manifest.source.as_ref().map(|source| &source.kind),
            Some(SourceKind::Git { .. })
        );
        if remote {
            anyhow::bail!(
                "state '{}' has no deployment and no config was found in the current directory; \
                 the default state tracks a remote repository — pass the repository URL or --repo",
                ctx.state_namespace
            );
        }
        if manifest.repo.as_deref().is_some_and(Path::is_dir) {
            return Ok(LocalSource::DefaultStateRepo(id));
        }
    }
    anyhow::bail!(
        "state '{}' has no deployment and no config was found in the current directory; \
         run from a repository or pass --repo",
        ctx.state_namespace
    )
}

// Prefer the original local repo path over the internal snapshot when it
// still exists, so the user keeps editing their own tree.
pub(crate) fn load_from_manifest(
    active_ctx: &mut GlobalCtx,
    manifest: &TransactionManifest,
) -> Result<(LoadedConfigSource, PathBuf)> {
    let mut repo = manifest.repo.clone().ok_or_else(|| {
        anyhow::anyhow!("active transaction {} has no repository path", manifest.id)
    })?;

    if repo.starts_with(xdg_state_home().join("malm"))
        && let Some(SourceKind::Local { path }) =
            manifest.source.as_ref().map(|source| &source.kind)
        && path.is_dir()
    {
        repo = path.clone();
    }

    active_ctx.repo = Some(repo.clone());
    if active_ctx.config.is_none() {
        active_ctx.config = manifest.config.clone();
    }
    if active_ctx.profile.is_none() {
        active_ctx.profile = manifest.profile.clone();
    }

    let mut loaded = match manifest.source.as_ref().map(|source| &source.kind) {
        Some(SourceKind::Git { .. }) => {
            let snapshot = SourceSnapshot::from_id(manifest.source_snapshot_id.as_str())?;
            snapshot.require_on_disk()?;
            let config_relative = manifest
                .config
                .as_deref()
                .and_then(|config| config.strip_prefix(&repo).ok())
                .unwrap_or_else(|| Path::new("malm.kdl"));
            // Local includes require a grant from the recorded transaction or
            // tracked remote; source resolution never grants access itself.
            let grant = manifest.allow_local_includes
                || TrackedRemote::load_for_state(active_ctx.state_namespace.as_str())
                    .ok()
                    .flatten()
                    .is_some_and(|tracking| tracking.allow_local_includes);
            let loaded = load_snapshot_config(
                snapshot.repository().to_path_buf(),
                snapshot.repository().join(config_relative),
                manifest.source.clone().expect("matched Git source"),
                grant,
            )?;
            // Fail closed: silently dropping includes would change the plan
            // (possibly undeploying entries the includes declared).
            if !loaded.external_includes_skipped.is_empty() {
                let listing = loaded
                    .external_includes_skipped
                    .iter()
                    .map(|path| format!("    {}", path.display()))
                    .collect::<Vec<_>>()
                    .join("\n");
                anyhow::bail!(
                    "the stored remote config reads local files it was never granted access \
                     to:\n{listing}\n\
                     re-apply the source with --allow-local-includes to grant it"
                );
            }
            // Keep the recorded repository and config rooted in the same
            // durable snapshot so another source-less replay can recover the
            // nested config path.
            repo = snapshot.repository().to_path_buf();
            active_ctx.repo = Some(repo.clone());
            loaded
        }
        _ => load_local_config(active_ctx)?,
    };
    if let Some(source) = manifest.source.clone() {
        loaded.resolved.identity = source;
    }
    Ok((loaded, repo))
}

pub(crate) fn load_resolved_local(active_ctx: &mut GlobalCtx) -> Result<LoadedConfigSource> {
    match classify_local_source(active_ctx)? {
        LocalSource::Explicit | LocalSource::CwdConfig => load_local_config(active_ctx),
        LocalSource::Active(id) => {
            let manifest = TransactionStore::new().read(&id)?;
            if !active_ctx.json {
                println!(
                    "No source specified: using active deployment of state \"{}\" (<store:{}>)",
                    active_ctx.state_namespace,
                    transaction_alias(&id)
                );
            }
            load_from_manifest(active_ctx, &manifest).map(|(loaded, _)| loaded)
        }
        LocalSource::DefaultStateRepo(id) => {
            let manifest = TransactionStore::new().read(&id)?;
            adopt_default_state_repo(active_ctx, &manifest)?;
            load_local_config(active_ctx)
        }
    }
}

pub(crate) fn adopt_default_state_repo(
    active_ctx: &mut GlobalCtx,
    manifest: &TransactionManifest,
) -> Result<PathBuf> {
    let repo = manifest.repo.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "default state's transaction {} has no repository path",
            manifest.id
        )
    })?;
    if !active_ctx.json {
        println!(
            "No source specified: state '{}' has no deployment; using repo from state \"default\" ({})",
            active_ctx.state_namespace,
            repo.display()
        );
    }
    active_ctx.repo = Some(repo.clone());
    Ok(repo)
}
