use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
};

use malm_types::{Alias, Digest, PackNodeId, PackageId};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};

use crate::{
    BundledComponentV1, ComponentInterfaceV1, DependencySourceV1, GitObjectId, GitSourceV1, GitUrl,
    LOCK_SCHEMA_VERSION, LocalLocator, MAX_LOCK_BYTES, MAX_LOCK_EDGES, MAX_LOCK_NODES,
    PackManifestV1, PackSubdir, canonical::Encoder,
};

const MAX_DIRECT_DEPENDENCIES: usize = 256;
const MAX_COMPONENTS: usize = 256;

/// A source recorded by a lock node.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LockedSourceV1 {
    /// The source containing the reviewed root lock.
    Root,
    /// An exact HTTPS Git source.
    Git(GitSourceV1),
    /// A canonical path relative to the root pack.
    Local(LocalLocator),
}

impl LockedSourceV1 {
    fn from_dependency(source: &DependencySourceV1) -> Self {
        match source {
            DependencySourceV1::Git(source) => Self::Git(source.clone()),
            DependencySourceV1::Local(locator) => Self::Local(locator.clone()),
        }
    }
}

/// An edge in an importing pack's private alias scope.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LockedDependencyV1 {
    alias: Alias,
    target_node_id: PackNodeId,
}

impl LockedDependencyV1 {
    #[must_use]
    pub const fn new(alias: Alias, target_node_id: PackNodeId) -> Self {
        Self {
            alias,
            target_node_id,
        }
    }

    #[must_use]
    pub const fn alias(&self) -> &Alias {
        &self.alias
    }

    #[must_use]
    pub const fn target_node_id(&self) -> &PackNodeId {
        &self.target_node_id
    }
}

/// A component with its lock-owned execution profile.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LockedComponentV1 {
    name: malm_types::ContributionName,
    path: crate::PackPath,
    digest: Digest,
    interface: ComponentInterfaceV1,
    execution_profile: Digest,
}

impl LockedComponentV1 {
    #[must_use]
    pub const fn new(
        name: malm_types::ContributionName,
        path: crate::PackPath,
        digest: Digest,
        interface: ComponentInterfaceV1,
        execution_profile: Digest,
    ) -> Self {
        Self {
            name,
            path,
            digest,
            interface,
            execution_profile,
        }
    }

    /// Adds an execution profile to a component declaration.
    #[must_use]
    pub fn from_declaration(declaration: &BundledComponentV1, execution_profile: Digest) -> Self {
        Self::new(
            declaration.name().clone(),
            declaration.path().clone(),
            declaration.digest().clone(),
            declaration.interface(),
            execution_profile,
        )
    }

    #[must_use]
    pub const fn name(&self) -> &malm_types::ContributionName {
        &self.name
    }

    #[must_use]
    pub const fn path(&self) -> &crate::PackPath {
        &self.path
    }

    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn interface(&self) -> ComponentInterfaceV1 {
        self.interface
    }

    #[must_use]
    pub const fn execution_profile(&self) -> &Digest {
        &self.execution_profile
    }

    fn agrees_with(&self, declaration: &BundledComponentV1) -> bool {
        self.name() == declaration.name()
            && self.path() == declaration.path()
            && self.digest() == declaration.digest()
            && self.interface() == declaration.interface()
    }
}

/// A validated node in a locked pack graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedPackV1 {
    node_id: PackNodeId,
    package_id: PackageId,
    source: LockedSourceV1,
    content_digest: Digest,
    dependencies: Vec<LockedDependencyV1>,
    components: Vec<LockedComponentV1>,
}

impl LockedPackV1 {
    /// Validates a node and computes its content-derived ID.
    pub fn new(
        package_id: PackageId,
        source: LockedSourceV1,
        content_digest: Digest,
        mut dependencies: Vec<LockedDependencyV1>,
        mut components: Vec<LockedComponentV1>,
    ) -> Result<Self, LockValidationError> {
        if dependencies.len() > MAX_DIRECT_DEPENDENCIES {
            return Err(LockValidationError::NodeLimitExceeded {
                collection: "dependencies",
                limit: MAX_DIRECT_DEPENDENCIES,
                actual: dependencies.len(),
            });
        }
        if components.len() > MAX_COMPONENTS {
            return Err(LockValidationError::NodeLimitExceeded {
                collection: "components",
                limit: MAX_COMPONENTS,
                actual: components.len(),
            });
        }

        dependencies.sort();
        for pair in dependencies.windows(2) {
            if pair[0].alias() == pair[1].alias() {
                return Err(LockValidationError::DuplicateAlias {
                    node_id: None,
                    alias: pair[1].alias().clone(),
                });
            }
        }
        components.sort();
        for pair in components.windows(2) {
            if pair[0].name() == pair[1].name() {
                return Err(LockValidationError::DuplicateComponent {
                    node_id: None,
                    name: pair[1].name().clone(),
                });
            }
        }

        let node_id = pack_node_id(&source, &package_id, &content_digest);
        Ok(Self {
            node_id,
            package_id,
            source,
            content_digest,
            dependencies,
            components,
        })
    }

    #[must_use]
    pub const fn node_id(&self) -> &PackNodeId {
        &self.node_id
    }

    #[must_use]
    pub const fn package_id(&self) -> &PackageId {
        &self.package_id
    }

    #[must_use]
    pub const fn source(&self) -> &LockedSourceV1 {
        &self.source
    }

    #[must_use]
    pub const fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    /// Returns dependencies in alias and target order.
    #[must_use]
    pub fn dependencies(&self) -> &[LockedDependencyV1] {
        &self.dependencies
    }

    /// Returns components in local-name and path order.
    #[must_use]
    pub fn components(&self) -> &[LockedComponentV1] {
        &self.components
    }
}

/// A structural or semantic lock/v1 graph failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LockValidationError {
    #[error("lock contains {actual} nodes; limit is {limit}")]
    TooManyNodes { limit: usize, actual: usize },
    #[error("lock contains {actual} edges; limit is {limit}")]
    TooManyEdges { limit: usize, actual: usize },
    #[error("locked node {collection} contains {actual} entries; limit is {limit}")]
    NodeLimitExceeded {
        collection: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("duplicate lock node {0}")]
    DuplicateNode(PackNodeId),
    #[error("lock node ID {found} does not match canonical ID {expected}")]
    NodeIdMismatch {
        found: PackNodeId,
        expected: PackNodeId,
    },
    #[error("root lock node {0} is missing")]
    MissingRoot(PackNodeId),
    #[error("lock must contain exactly one root source, found {actual}")]
    RootSourceCount { actual: usize },
    #[error("root source belongs to {found}, not named root {expected}")]
    RootSourceMismatch {
        expected: PackNodeId,
        found: PackNodeId,
    },
    #[error("lock nodes {first} and {second} claim different snapshots for one exact source")]
    ConflictingSource {
        first: PackNodeId,
        second: PackNodeId,
    },
    #[error("lock node {from} alias {alias} references missing target {target}")]
    MissingTarget {
        from: PackNodeId,
        alias: Alias,
        target: PackNodeId,
    },
    #[error("{} repeats alias {alias}", node_scope(node_id))]
    DuplicateAlias {
        node_id: Option<PackNodeId>,
        alias: Alias,
    },
    #[error("{} repeats component {name}", node_scope(node_id))]
    DuplicateComponent {
        node_id: Option<PackNodeId>,
        name: malm_types::ContributionName,
    },
    #[error("locked dependency cycle: {}", render_cycle(nodes))]
    Cycle {
        /// The first node is repeated at the end.
        nodes: Vec<PackNodeId>,
    },
    #[error("lock node {0} is unreachable from the root")]
    UnreachableNode(PackNodeId),
    #[error("lock node {node_id} disagrees with its manifest: {detail}")]
    ManifestMismatch { node_id: PackNodeId, detail: String },
}

fn node_scope(node_id: &Option<PackNodeId>) -> String {
    match node_id {
        Some(node) => format!("lock node {node}"),
        None => "locked node".to_owned(),
    }
}

fn render_cycle(nodes: &[PackNodeId]) -> String {
    nodes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// A normalized, acyclic lock/v1 graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockV1 {
    root_node_id: PackNodeId,
    nodes: Vec<LockedPackV1>,
}

impl LockV1 {
    /// Validates and canonicalizes a complete lock graph.
    pub fn new(
        root_node_id: PackNodeId,
        mut nodes: Vec<LockedPackV1>,
    ) -> Result<Self, LockValidationError> {
        if nodes.len() > MAX_LOCK_NODES {
            return Err(LockValidationError::TooManyNodes {
                limit: MAX_LOCK_NODES,
                actual: nodes.len(),
            });
        }
        nodes.sort_by(|left, right| left.node_id().cmp(right.node_id()));
        for pair in nodes.windows(2) {
            if pair[0].node_id() == pair[1].node_id() {
                return Err(LockValidationError::DuplicateNode(
                    pair[1].node_id().clone(),
                ));
            }
        }

        let index = nodes
            .iter()
            .enumerate()
            .map(|(position, node)| (node.node_id().clone(), position))
            .collect::<BTreeMap<_, _>>();
        if !index.contains_key(&root_node_id) {
            return Err(LockValidationError::MissingRoot(root_node_id));
        }

        let roots = nodes
            .iter()
            .filter(|node| matches!(node.source(), LockedSourceV1::Root))
            .collect::<Vec<_>>();
        if roots.len() != 1 {
            return Err(LockValidationError::RootSourceCount {
                actual: roots.len(),
            });
        }
        if roots[0].node_id() != &root_node_id {
            return Err(LockValidationError::RootSourceMismatch {
                expected: root_node_id,
                found: roots[0].node_id().clone(),
            });
        }

        let mut sources = BTreeMap::new();
        for node in &nodes {
            if matches!(node.source(), LockedSourceV1::Root) {
                continue;
            }
            if let Some(first) = sources.insert(node.source(), node.node_id()) {
                return Err(LockValidationError::ConflictingSource {
                    first: first.clone(),
                    second: node.node_id().clone(),
                });
            }
        }

        let edge_count = nodes.iter().map(|node| node.dependencies().len()).sum();
        if edge_count > MAX_LOCK_EDGES {
            return Err(LockValidationError::TooManyEdges {
                limit: MAX_LOCK_EDGES,
                actual: edge_count,
            });
        }
        for node in &nodes {
            for edge in node.dependencies() {
                if !index.contains_key(edge.target_node_id()) {
                    return Err(LockValidationError::MissingTarget {
                        from: node.node_id().clone(),
                        alias: edge.alias().clone(),
                        target: edge.target_node_id().clone(),
                    });
                }
            }
        }

        if let Some(cycle) = find_cycle(&nodes, &index) {
            return Err(LockValidationError::Cycle { nodes: cycle });
        }
        let reachable = reachable_nodes(&root_node_id, &nodes, &index);
        if let Some(node) = nodes
            .iter()
            .find(|node| !reachable.contains(node.node_id()))
        {
            return Err(LockValidationError::UnreachableNode(node.node_id().clone()));
        }

        Ok(Self {
            root_node_id,
            nodes,
        })
    }

    #[must_use]
    pub const fn root_node_id(&self) -> &PackNodeId {
        &self.root_node_id
    }

    /// Returns nodes in canonical ID order.
    #[must_use]
    pub fn nodes(&self) -> &[LockedPackV1] {
        &self.nodes
    }

    #[must_use]
    pub fn node(&self, node_id: &PackNodeId) -> Option<&LockedPackV1> {
        self.nodes
            .binary_search_by(|node| node.node_id().cmp(node_id))
            .ok()
            .map(|position| &self.nodes[position])
    }

    /// Verifies a manifest against its node and outgoing edges.
    pub fn validate_manifest(
        &self,
        node_id: &PackNodeId,
        manifest: &PackManifestV1,
    ) -> Result<(), LockValidationError> {
        let node = self
            .node(node_id)
            .ok_or_else(|| LockValidationError::MissingRoot(node_id.clone()))?;
        let mismatch = |detail: String| LockValidationError::ManifestMismatch {
            node_id: node_id.clone(),
            detail,
        };

        if node.package_id() != manifest.package_id() {
            return Err(mismatch(format!(
                "package ID is {}, manifest declares {}",
                node.package_id(),
                manifest.package_id()
            )));
        }
        if node.components().len() != manifest.components().len()
            || !node
                .components()
                .iter()
                .zip(manifest.components())
                .all(|(locked, declaration)| locked.agrees_with(declaration))
        {
            return Err(mismatch("bundled component records differ".to_owned()));
        }
        if node.dependencies().len() != manifest.dependencies().len() {
            return Err(mismatch(format!(
                "lock has {} dependencies, manifest declares {}",
                node.dependencies().len(),
                manifest.dependencies().len()
            )));
        }

        for declaration in manifest.dependencies() {
            let edge = node
                .dependencies()
                .iter()
                .find(|edge| edge.alias() == declaration.alias())
                .ok_or_else(|| {
                    mismatch(format!(
                        "alias {} is missing from the lock",
                        declaration.alias()
                    ))
                })?;
            let target = self
                .node(edge.target_node_id())
                .expect("target existence validated by LockV1::new");
            if target.package_id() != declaration.package_id() {
                return Err(mismatch(format!(
                    "alias {} targets package {}, manifest expects {}",
                    declaration.alias(),
                    target.package_id(),
                    declaration.package_id()
                )));
            }
            let expected_source = LockedSourceV1::from_dependency(declaration.source());
            if target.source() != &expected_source {
                return Err(mismatch(format!(
                    "alias {} targets a different source",
                    declaration.alias()
                )));
            }
        }
        Ok(())
    }
}

fn find_cycle(
    nodes: &[LockedPackV1],
    index: &BTreeMap<PackNodeId, usize>,
) -> Option<Vec<PackNodeId>> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Mark {
        Visiting,
        Complete,
    }

    let mut marks = BTreeMap::new();
    for start in nodes.iter().map(LockedPackV1::node_id) {
        if marks.contains_key(start) {
            continue;
        }
        marks.insert(start.clone(), Mark::Visiting);
        let mut stack = vec![(start.clone(), 0_usize)];

        while let Some((current, next_edge)) = stack.last_mut() {
            let node = &nodes[index[current]];
            if *next_edge == node.dependencies().len() {
                let current = current.clone();
                stack.pop();
                marks.insert(current, Mark::Complete);
                continue;
            }

            let target = node.dependencies()[*next_edge].target_node_id().clone();
            *next_edge += 1;
            match marks.get(&target) {
                Some(Mark::Complete) => {}
                Some(Mark::Visiting) => {
                    let start = stack
                        .iter()
                        .position(|(node, _)| node == &target)
                        .expect("visiting node is present on the DFS stack");
                    let mut cycle = stack[start..]
                        .iter()
                        .map(|(node, _)| node.clone())
                        .collect::<Vec<_>>();
                    cycle.push(target);
                    return Some(cycle);
                }
                None => {
                    marks.insert(target.clone(), Mark::Visiting);
                    stack.push((target, 0));
                }
            }
        }
    }
    None
}

fn reachable_nodes(
    root: &PackNodeId,
    nodes: &[LockedPackV1],
    index: &BTreeMap<PackNodeId, usize>,
) -> BTreeSet<PackNodeId> {
    let mut reachable = BTreeSet::new();
    let mut pending = vec![root.clone()];
    while let Some(current) = pending.pop() {
        if !reachable.insert(current.clone()) {
            continue;
        }
        pending.extend(
            nodes[index[&current]]
                .dependencies()
                .iter()
                .rev()
                .map(|edge| edge.target_node_id().clone()),
        );
    }
    reachable
}

/// Computes a canonical node ID from its source, package, and content.
#[must_use]
pub fn pack_node_id(
    source: &LockedSourceV1,
    package_id: &PackageId,
    content_digest: &Digest,
) -> PackNodeId {
    let mut encoder = Encoder::new(b"malm-pack-node\0");
    encode_source(&mut encoder, source);
    encoder.text(package_id.as_str());
    encoder.text(content_digest.as_str());
    PackNodeId::new(encoder.finish())
}

/// Computes an order-independent semantic digest for a validated lock graph.
#[must_use]
pub fn lock_graph_digest(lock: &LockV1) -> Digest {
    let mut encoder = Encoder::new(b"malm-lock-graph\0");
    encoder.u64(u64::from(LOCK_SCHEMA_VERSION));
    encoder.text(lock.root_node_id().as_ref());
    encoder.u64(malm_types::usize_to_u64(lock.nodes().len()));
    for node in lock.nodes() {
        encoder.text(node.node_id().as_ref());
        encoder.text(node.package_id().as_str());
        encode_source(&mut encoder, node.source());
        encoder.text(node.content_digest().as_str());
        encoder.u64(malm_types::usize_to_u64(node.dependencies().len()));
        for edge in node.dependencies() {
            encoder.text(edge.alias().as_str());
            encoder.text(edge.target_node_id().as_ref());
        }
        encoder.u64(malm_types::usize_to_u64(node.components().len()));
        for component in node.components() {
            encoder.text(component.name().as_str());
            encoder.text(component.path().as_str());
            encoder.text(component.digest().as_str());
            encoder.text(component.interface().as_str());
            encoder.text(component.execution_profile().as_str());
        }
    }
    encoder.finish()
}

fn encode_source(encoder: &mut Encoder<'_>, source: &LockedSourceV1) {
    match source {
        LockedSourceV1::Root => encoder.tag(0),
        LockedSourceV1::Git(source) => {
            encoder.tag(1);
            encoder.text(source.url().as_str());
            encoder.text(source.commit().as_str());
            encoder.text(source.subdir().as_str());
        }
        LockedSourceV1::Local(locator) => {
            encoder.tag(2);
            encoder.text(locator.as_str());
        }
    }
}

/// Failure to decode a strict lock/v1 document.
#[derive(Debug, thiserror::Error)]
pub enum LockReadError {
    #[error("lock is {actual} bytes; limit is {limit}")]
    TooLarge { limit: usize, actual: usize },
    #[error("malformed lock/v1 JSON: {0}")]
    MalformedJson(String),
    #[error("unsupported lock schema: expected exactly {expected}, found {found}")]
    UnsupportedVersion { expected: u32, found: u64 },
    #[error("invalid lock/v1 graph: {0}")]
    InvalidLock(#[source] LockValidationError),
}

/// Decodes bounded, strict JSON into a validated lock graph.
pub fn decode_lock_v1(bytes: &[u8]) -> Result<LockV1, LockReadError> {
    if bytes.len() > MAX_LOCK_BYTES {
        return Err(LockReadError::TooLarge {
            limit: MAX_LOCK_BYTES,
            actual: bytes.len(),
        });
    }
    let _: NoDuplicateKeys = serde_json::from_slice(bytes)
        .map_err(|error| LockReadError::MalformedJson(error.to_string()))?;
    let probe: VersionProbe = serde_json::from_slice(bytes)
        .map_err(|error| LockReadError::MalformedJson(error.to_string()))?;
    if probe.schema_version != u64::from(LOCK_SCHEMA_VERSION) {
        return Err(LockReadError::UnsupportedVersion {
            expected: LOCK_SCHEMA_VERSION,
            found: probe.schema_version,
        });
    }
    let wire: LockWireV1 = serde_json::from_slice(bytes)
        .map_err(|error| LockReadError::MalformedJson(error.to_string()))?;
    if wire.schema_version != LOCK_SCHEMA_VERSION {
        return Err(LockReadError::UnsupportedVersion {
            expected: LOCK_SCHEMA_VERSION,
            found: u64::from(wire.schema_version),
        });
    }
    wire.try_into().map_err(LockReadError::InvalidLock)
}

/// Encodes deterministic JSON with one trailing newline.
#[must_use]
pub fn encode_lock_v1(lock: &LockV1) -> Vec<u8> {
    let wire = LockWireV1::from(lock);
    let mut bytes = serde_json::to_vec_pretty(&wire)
        .expect("validated lock/v1 values always serialize to JSON");
    bytes.push(b'\n');
    bytes
}

#[derive(Deserialize)]
struct VersionProbe {
    schema_version: u64,
}

#[derive(Clone, Copy)]
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(Self)
    }
}

impl<'de> Visitor<'de> for NoDuplicateKeys {
    type Value = Self;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(self)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(self)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(self)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(self)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(self)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<Self>()?.is_some() {}
        Ok(self)
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format_args!(
                    "duplicate object key {key:?}"
                )));
            }
            let _: Self = object.next_value()?;
        }
        Ok(self)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockWireV1 {
    schema_version: u32,
    root_node_id: PackNodeId,
    nodes: Vec<NodeWireV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeWireV1 {
    node_id: PackNodeId,
    package_id: PackageId,
    source: SourceWireV1,
    content_digest: Digest,
    dependencies: Vec<DependencyWireV1>,
    components: Vec<ComponentWireV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum SourceWireV1 {
    Root,
    Git {
        url: GitUrl,
        commit: GitObjectId,
        subdir: PackSubdir,
    },
    Local {
        locator: LocalLocator,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyWireV1 {
    alias: Alias,
    target_node_id: PackNodeId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentWireV1 {
    name: malm_types::ContributionName,
    path: crate::PackPath,
    digest: Digest,
    interface: String,
    execution_profile: Digest,
}

impl TryFrom<LockWireV1> for LockV1 {
    type Error = LockValidationError;

    fn try_from(wire: LockWireV1) -> Result<Self, Self::Error> {
        let nodes = wire
            .nodes
            .into_iter()
            .map(LockedPackV1::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(wire.root_node_id, nodes)
    }
}

impl TryFrom<NodeWireV1> for LockedPackV1 {
    type Error = LockValidationError;

    fn try_from(wire: NodeWireV1) -> Result<Self, Self::Error> {
        let found = wire.node_id;
        let source = match wire.source {
            SourceWireV1::Root => LockedSourceV1::Root,
            SourceWireV1::Git {
                url,
                commit,
                subdir,
            } => LockedSourceV1::Git(GitSourceV1::new(url, commit, subdir)),
            SourceWireV1::Local { locator } => LockedSourceV1::Local(locator),
        };
        let dependencies = wire
            .dependencies
            .into_iter()
            .map(|edge| LockedDependencyV1::new(edge.alias, edge.target_node_id))
            .collect();
        let components = wire
            .components
            .into_iter()
            .map(|component| {
                if component.interface != ComponentInterfaceV1::FormatComponentV1.as_str() {
                    return Err(LockValidationError::ManifestMismatch {
                        node_id: found.clone(),
                        detail: format!(
                            "component {} has unsupported interface {:?}",
                            component.name, component.interface
                        ),
                    });
                }
                Ok(LockedComponentV1::new(
                    component.name,
                    component.path,
                    component.digest,
                    ComponentInterfaceV1::FormatComponentV1,
                    component.execution_profile,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let node = Self::new(
            wire.package_id,
            source,
            wire.content_digest,
            dependencies,
            components,
        )?;
        if &found != node.node_id() {
            return Err(LockValidationError::NodeIdMismatch {
                found,
                expected: node.node_id().clone(),
            });
        }
        Ok(node)
    }
}

impl From<&LockV1> for LockWireV1 {
    fn from(lock: &LockV1) -> Self {
        Self {
            schema_version: LOCK_SCHEMA_VERSION,
            root_node_id: lock.root_node_id().clone(),
            nodes: lock.nodes().iter().map(NodeWireV1::from).collect(),
        }
    }
}

impl From<&LockedPackV1> for NodeWireV1 {
    fn from(node: &LockedPackV1) -> Self {
        Self {
            node_id: node.node_id().clone(),
            package_id: node.package_id().clone(),
            source: SourceWireV1::from(node.source()),
            content_digest: node.content_digest().clone(),
            dependencies: node
                .dependencies()
                .iter()
                .map(|edge| DependencyWireV1 {
                    alias: edge.alias().clone(),
                    target_node_id: edge.target_node_id().clone(),
                })
                .collect(),
            components: node
                .components()
                .iter()
                .map(|component| ComponentWireV1 {
                    name: component.name().clone(),
                    path: component.path().clone(),
                    digest: component.digest().clone(),
                    interface: component.interface().as_str().to_owned(),
                    execution_profile: component.execution_profile().clone(),
                })
                .collect(),
        }
    }
}

impl From<&LockedSourceV1> for SourceWireV1 {
    fn from(source: &LockedSourceV1) -> Self {
        match source {
            LockedSourceV1::Root => Self::Root,
            LockedSourceV1::Git(source) => Self::Git {
                url: source.url().clone(),
                commit: source.commit().clone(),
                subdir: source.subdir().clone(),
            },
            LockedSourceV1::Local(locator) => Self::Local {
                locator: locator.clone(),
            },
        }
    }
}
