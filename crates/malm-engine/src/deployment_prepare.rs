use std::path::PathBuf;

use malm_pack::{LockV1, LockedSourceV1};
use malm_types::{ContributionName, DeploymentName, NamespaceName, PreparedDeploymentV1};

use crate::{
    CommitError, Engine, EngineError, GitAcquisitionConfig, GraphAcquisitionError,
    GraphAcquisitionInputs, StaticPrepareError, config_prepare, graph_acquisition,
};

/// Closed choice between verified CAS assembly and explicitly authorized acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticGraphAcquisitionV1 {
    /// Load every exact locked pack only from the verified v1 CAS.
    Cached,
    /// Recapture the root/local sources and acquire missing exact Git packs.
    Acquire {
        /// Absolute root pack whose current bytes must match the lock.
        root_source: PathBuf,
        /// Complete explicit local, Git URL, and scratch authority.
        inputs: GraphAcquisitionInputs,
        /// Trusted absolute Git executable and bounds, required only for Git locks.
        git: Option<GitAcquisitionConfig>,
    },
}

/// Borrowed authority and deployment state for one static profile prepare.
#[derive(Clone, Debug)]
pub struct StaticProfile<'a> {
    /// Locked graph whose verified packs supply the profile's source bytes.
    pub graph: &'a malm_module_graph::AssembledLockedGraphV1,
    /// Authorization carried by every format-component transform in this profile.
    pub component_authorization: &'a malm_format_component_api::FormatComponentAuthorizationV1,
    /// Namespace whose head the prepared plan will update.
    pub namespace: NamespaceName,
    /// Stable target authority that will own the prepared plan's outputs.
    pub target_authority: DeploymentName,
    /// Existing namespace head the prepare must observe; `None` for a new namespace.
    pub expected_head: Option<malm_types::Digest>,
}

impl StaticGraphAcquisitionV1 {
    /// Selects verified offline CAS assembly.
    #[must_use]
    pub const fn cached() -> Self {
        Self::Cached
    }

    /// Selects current source capture plus exact Git acquisition when required.
    #[must_use]
    pub fn acquire(
        root_source: impl Into<PathBuf>,
        inputs: GraphAcquisitionInputs,
        git: Option<GitAcquisitionConfig>,
    ) -> Self {
        Self::Acquire {
            root_source: root_source.into(),
            inputs,
            git,
        }
    }
}

/// Complete semantic request for one locked static deployment prepare.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticDeploymentPrepareRequestV1 {
    lock: LockV1,
    acquisition: StaticGraphAcquisitionV1,
    component_authorization: malm_format_component_api::FormatComponentAuthorizationV1,
    profile: Option<ContributionName>,
    namespace: NamespaceName,
    target_authority: DeploymentName,
}

impl StaticDeploymentPrepareRequestV1 {
    #[must_use]
    pub const fn new(
        lock: LockV1,
        acquisition: StaticGraphAcquisitionV1,
        component_authorization: malm_format_component_api::FormatComponentAuthorizationV1,
        profile: Option<ContributionName>,
        namespace: NamespaceName,
        target_authority: DeploymentName,
    ) -> Self {
        Self {
            lock,
            acquisition,
            component_authorization,
            profile,
            namespace,
            target_authority,
        }
    }

    #[must_use]
    pub const fn lock(&self) -> &LockV1 {
        &self.lock
    }

    #[must_use]
    pub const fn acquisition(&self) -> &StaticGraphAcquisitionV1 {
        &self.acquisition
    }

    #[must_use]
    pub const fn component_authorization(
        &self,
    ) -> &malm_format_component_api::FormatComponentAuthorizationV1 {
        &self.component_authorization
    }

    #[must_use]
    pub const fn profile(&self) -> Option<&ContributionName> {
        self.profile.as_ref()
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    #[must_use]
    pub const fn target_authority(&self) -> &DeploymentName {
        &self.target_authority
    }
}

/// Failure while acquiring, evaluating, and durably preparing one static deployment.
// The cause already appears in Display, and source() would duplicate it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StaticDeploymentPrepareError {
    /// A non-cached Git lock had no explicit Git process configuration.
    #[error("Git process configuration is required for a non-cached lock containing Git nodes")]
    GitConfigurationRequired,
    /// Git authority was supplied for a lock containing no Git nodes.
    #[error("Git acquisition authority requires a lock containing Git nodes")]
    GitConfigurationNotApplicable,
    /// Current source capture or exact Git acquisition failed.
    #[error("{0}")]
    GraphAcquisition(GraphAcquisitionError),
    /// Verified cached objects did not assemble into the exact lock graph.
    #[error("{0}")]
    GraphAssembly(malm_module_graph::GraphAssemblyError<EngineError>),
    /// Active generation inspection failed before target observation.
    #[error("{0}")]
    State(CommitError),
    /// Static config evaluation or durable plan publication failed.
    #[error("{0}")]
    Static(StaticPrepareError),
}

pub(super) fn prepare(
    engine: &Engine,
    request: &StaticDeploymentPrepareRequestV1,
) -> Result<PreparedDeploymentV1, StaticDeploymentPrepareError> {
    let graph = match request.acquisition() {
        StaticGraphAcquisitionV1::Cached => engine
            .assemble_cached_pack_graph_raw(request.lock())
            .map_err(StaticDeploymentPrepareError::GraphAssembly)?,
        StaticGraphAcquisitionV1::Acquire {
            root_source,
            inputs,
            git,
        } => {
            let has_git = request
                .lock()
                .nodes()
                .iter()
                .any(|node| matches!(node.source(), LockedSourceV1::Git(_)));
            if has_git {
                let git = git
                    .as_ref()
                    .ok_or(StaticDeploymentPrepareError::GitConfigurationRequired)?;
                graph_acquisition::acquire(engine, root_source, request.lock(), inputs, git)
                    .map_err(StaticDeploymentPrepareError::GraphAcquisition)?
            } else {
                if git.is_some()
                    || !inputs.git_urls().is_empty()
                    || !inputs.git_scratch_roots().is_empty()
                {
                    return Err(StaticDeploymentPrepareError::GitConfigurationNotApplicable);
                }
                graph_acquisition::acquire_local(
                    engine,
                    root_source,
                    request.lock(),
                    inputs.local_locators(),
                )
                .map_err(StaticDeploymentPrepareError::GraphAcquisition)?
            }
        }
    };
    let expected_head = engine
        .committer_v1()
        .and_then(|committer| committer.inspect_state_v1(request.namespace()))
        .map_err(StaticDeploymentPrepareError::State)?
        .head()
        .cloned();
    config_prepare::prepare(
        config_prepare::StaticPrepareContext {
            engine,
            graph: &graph,
            component_authorization: request.component_authorization(),
            namespace: request.namespace().clone(),
            target_authority: request.target_authority().clone(),
            expected_head,
            tracked_root: None,
        },
        request.profile(),
        None,
    )
    .map_err(StaticDeploymentPrepareError::Static)
}
