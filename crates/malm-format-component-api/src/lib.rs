//! Exact authorization and version identifiers for the capability-free format ABI.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use malm_types::Digest;
use serde::{Deserialize, Serialize};

/// The exact pack and lock spelling of the component interface.
pub const FORMAT_COMPONENT_INTERFACE_V1: &str = "format-component/v1";

/// The component-model contract mirrored by the deterministic host.
pub const WIT_SOURCE: &str = include_str!("../wit/malm-format-component.wit");

/// Exact component authorization presented to the isolated execution host.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatComponentAuthorizationV1 {
    digests: BTreeSet<Digest>,
}

impl FormatComponentAuthorizationV1 {
    #[must_use]
    pub fn new(digests: impl IntoIterator<Item = Digest>) -> Self {
        Self {
            digests: digests.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn permits(&self, digest: &Digest) -> bool {
        self.digests.contains(digest)
    }

    /// Iterates over authorized exact digests in canonical order.
    pub fn digests(&self) -> impl ExactSizeIterator<Item = &Digest> {
        self.digests.iter()
    }
}
