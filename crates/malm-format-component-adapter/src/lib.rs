//! Connects the Engine format-component port to the isolated host during prepare.

#![forbid(unsafe_code)]

use malm_config::{TransformIdentityV1, TransformImplementationV1, TransformRequestV1};
use malm_engine::{FormatComponentExecutionIssue, FormatComponentExecutionPort};
pub use malm_format_component_api::FORMAT_COMPONENT_INTERFACE_V1;
use malm_format_component_api::FormatComponentAuthorizationV1;
use malm_format_component_host::{
    ComponentAdmissionError, FormatComponentHost, FormatComponentInvocationError,
};

/// Returns the current host execution profile without initializing Wasmtime or its cache.
#[must_use]
pub fn current_host_execution_profile_digest_v1() -> malm_types::Digest {
    malm_format_component_host::execution_profile_digest_v1()
}

/// In-process component adapter for embedders that opt in to Wasmtime.
///
/// The adapter initializes the Wasmtime host and optional on-disk compilation
/// cache on first use. Commands that do not invoke a component do not incur
/// initialization work or touch the cache directory.
#[derive(Debug)]
pub struct InProcessFormatComponentExecutionPort {
    cache_dir: Option<std::path::PathBuf>,
    host: std::sync::OnceLock<Result<FormatComponentHost, FormatComponentExecutionIssue>>,
}

impl InProcessFormatComponentExecutionPort {
    /// Creates an adapter that initializes a private host and watchdog on first use.
    pub fn new() -> Result<Self, FormatComponentExecutionIssue> {
        Ok(Self {
            cache_dir: None,
            host: std::sync::OnceLock::new(),
        })
    }

    /// Creates a lazy adapter with a persistent compilation cache directory.
    ///
    /// An unusable directory silently falls back to per-process compilation.
    pub fn with_compile_cache(
        cache_dir: &std::path::Path,
    ) -> Result<Self, FormatComponentExecutionIssue> {
        Ok(Self {
            cache_dir: Some(cache_dir.to_path_buf()),
            host: std::sync::OnceLock::new(),
        })
    }

    fn host(&self) -> Result<&FormatComponentHost, FormatComponentExecutionIssue> {
        self.host
            .get_or_init(|| {
                match &self.cache_dir {
                    Some(cache_dir) => FormatComponentHost::with_compile_cache(cache_dir),
                    None => FormatComponentHost::new(),
                }
                .map_err(|error| FormatComponentExecutionIssue::new(error.to_string()))
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

impl FormatComponentExecutionPort for InProcessFormatComponentExecutionPort {
    fn invoke(
        &self,
        authorization: &FormatComponentAuthorizationV1,
        identity: &TransformIdentityV1,
        component_bytes: &[u8],
        request: &TransformRequestV1,
    ) -> Result<
        Result<malm_config::TransformResponseV1, malm_config::TransformFailureV1>,
        FormatComponentExecutionIssue,
    > {
        let TransformImplementationV1::Component {
            component_digest,
            interface_version,
            execution_profile_digest,
        } = identity.implementation()
        else {
            return Err(FormatComponentExecutionIssue::new(
                "format-component port requires a component transform identity",
            ));
        };
        if interface_version != FORMAT_COMPONENT_INTERFACE_V1 {
            return Err(FormatComponentExecutionIssue::new(
                "component identity carries an unsupported interface version",
            ));
        }
        let host = self.host()?;
        if execution_profile_digest != host.execution_profile_digest() {
            return Err(FormatComponentExecutionIssue::new(format!(
                "locked execution profile {} does not match host profile {}",
                execution_profile_digest,
                host.execution_profile_digest()
            )));
        }
        host.admit_component(authorization, component_digest, component_bytes)
            .map_err(admission_issue)?
            .transform(request)
            .map_err(invocation_issue)
    }
}

fn admission_issue(error: ComponentAdmissionError) -> FormatComponentExecutionIssue {
    FormatComponentExecutionIssue::new(error.to_string())
}

fn invocation_issue(error: FormatComponentInvocationError) -> FormatComponentExecutionIssue {
    FormatComponentExecutionIssue::new(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use malm_config::{CanonicalTypedDocumentV1, RichNameV1, TransformRequestV1, TypedValueV1};
    use malm_engine::FormatComponentExecutionPort;
    use malm_types::Digest;

    use super::{InProcessFormatComponentExecutionPort, current_host_execution_profile_digest_v1};

    fn request() -> TransformRequestV1 {
        TransformRequestV1::new(
            CanonicalTypedDocumentV1::new(TypedValueV1::record(BTreeMap::new()).unwrap()).unwrap(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn current_profile_helper_delegates_without_constructing_the_host() {
        let adapter = InProcessFormatComponentExecutionPort::new().unwrap();
        assert!(adapter.host.get().is_none());
        assert_eq!(
            current_host_execution_profile_digest_v1(),
            malm_format_component_host::execution_profile_digest_v1()
        );
        assert!(adapter.host.get().is_none());
    }

    #[test]
    fn adapter_rejects_non_component_identity_before_admission() {
        let adapter = InProcessFormatComponentExecutionPort::new().unwrap();
        let identity = malm_config::TransformIdentityV1::built_in(
            RichNameV1::new("canonical-json").unwrap(),
            "builtin/1",
        )
        .unwrap();
        let error = adapter
            .invoke(
                &malm_format_component_api::FormatComponentAuthorizationV1::default(),
                &identity,
                b"not a component",
                &request(),
            )
            .unwrap_err();
        assert!(
            error
                .reason()
                .contains("requires a component transform identity")
        );
    }

    #[test]
    fn adapter_rejects_a_different_locked_execution_profile_before_admission() {
        let adapter = InProcessFormatComponentExecutionPort::new().unwrap();
        let component = Digest::sha256(b"component");
        let identity = malm_config::TransformIdentityV1::component(
            RichNameV1::new("formatter").unwrap(),
            component.clone(),
            malm_format_component_api::FORMAT_COMPONENT_INTERFACE_V1,
            Digest::sha256(b"different profile"),
        )
        .unwrap();
        let error = adapter
            .invoke(
                &malm_format_component_api::FormatComponentAuthorizationV1::new([component]),
                &identity,
                b"not a component",
                &request(),
            )
            .unwrap_err();
        assert!(error.reason().contains("does not match host profile"));
    }
}
