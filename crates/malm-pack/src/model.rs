use std::{collections::BTreeSet, fmt};

use malm_types::{Alias, ContributionName, Digest, PackageId};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use url::Url;

use crate::{
    LOCK_FILE, LOCK_STAGING_FILE, MAX_PACK_FILE_BYTES, MAX_PACK_TREE_BYTES, MAX_PACK_TREE_ENTRIES,
    PACK_MANIFEST_FILE, canonical::Encoder,
};

pub(crate) const MAX_PACK_PATH_BYTES: usize = 1024;
const MAX_PACK_PATH_SEGMENTS: usize = 32;
const MAX_PATH_SEGMENT_BYTES: usize = 255;
const MAX_LOCAL_LOCATOR_BYTES: usize = 4096;
const MAX_LOCAL_LOCATOR_SEGMENTS: usize = 64;
const MAX_GIT_URL_BYTES: usize = 2048;
const MAX_MODULES: usize = 4096;
const MAX_DIRECT_DEPENDENCIES: usize = 256;
const MAX_RESOURCES_PER_KIND: usize = 4096;
const MAX_COMPONENTS: usize = 256;

/// An invalid scalar in a pack or lock contract.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid {kind} ({value_len} bytes): {reason}")]
pub struct ValueError {
    kind: &'static str,
    value_len: usize,
    reason: &'static str,
}

impl ValueError {
    fn new(kind: &'static str, value: &str, reason: &'static str) -> Self {
        Self {
            kind,
            value_len: value.len(),
            reason,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    #[must_use]
    pub const fn value_len(&self) -> usize {
        self.value_len
    }

    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

malm_types::validated_string! {
    /// A validated path relative to a pack root.
    pub struct PackPath;
    error: ValueError;
    validate: validate_pack_path;
    make_error: |value, reason| ValueError::new("pack path", &value, reason);
    impl: serde;
}

/// A regular file in a logical pack object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackFileV1 {
    path: PackPath,
    bytes: Vec<u8>,
}

impl PackFileV1 {
    #[must_use]
    pub fn new(path: PackPath, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path,
            bytes: bytes.into(),
        }
    }

    #[must_use]
    pub const fn path(&self) -> &PackPath {
        &self.path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_parts(self) -> (PackPath, Vec<u8>) {
        (self.path, self.bytes)
    }
}

malm_types::validated_string! {
    /// A canonical lexical path relative to the root pack.
    pub struct LocalLocator;
    error: ValueError;
    validate: validate_local_locator;
    make_error: |value, reason| ValueError::new("local locator", &value, reason);
    impl: serde;
}

malm_types::validated_string! {
    /// A full algorithm-tagged Git object ID.
    pub struct GitObjectId;
    error: ValueError;
    validate: validate_git_object_id;
    make_error: |value, reason| ValueError::new("Git object ID", &value, reason);
    impl: serde;
}

malm_types::validated_string! {
    /// A normalized HTTPS Git URL without credentials.
    pub struct GitUrl;
    error: ValueError;
    normalize: canonicalize_https_url;
    make_error: |value, reason| ValueError::new("Git URL", &value, reason);
    impl: serde;
}

fn contains_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn is_reserved_segment(segment: &str) -> bool {
    matches!(segment, ".git" | LOCK_FILE | LOCK_STAGING_FILE)
}

fn validate_pack_path(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.len() > MAX_PACK_PATH_BYTES {
        return Err("must be at most 1024 bytes");
    }
    if value.starts_with('/') {
        return Err("must be relative to the pack root");
    }
    if value.contains('\\') {
        return Err("must use slash separators");
    }
    if contains_control(value) {
        return Err("must not contain control characters");
    }

    let segments = value.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_PACK_PATH_SEGMENTS {
        return Err("must contain at most 32 segments");
    }
    for segment in segments {
        if segment.is_empty() {
            return Err("must not contain empty segments");
        }
        if matches!(segment, "." | "..") {
            return Err("must not contain dot segments");
        }
        if segment.len() > MAX_PATH_SEGMENT_BYTES {
            return Err("segments must be at most 255 bytes");
        }
        if is_reserved_segment(segment) {
            return Err("must not enter reserved .git or lock paths");
        }
    }
    Ok(())
}

fn validate_local_locator(value: &str) -> Result<(), &'static str> {
    if value == "." {
        return Ok(());
    }
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.len() > MAX_LOCAL_LOCATOR_BYTES {
        return Err("must be at most 4096 bytes");
    }
    if value.starts_with('/') {
        return Err("must be relative to the root pack");
    }
    if value.contains('\\') {
        return Err("must use slash separators");
    }
    if contains_control(value) {
        return Err("must not contain control characters");
    }

    let segments = value.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_LOCAL_LOCATOR_SEGMENTS {
        return Err("must contain at most 64 segments");
    }
    let mut saw_normal = false;
    for segment in segments {
        if segment.is_empty() {
            return Err("must not contain empty segments");
        }
        if segment == "." {
            return Err("must already be lexically normalized");
        }
        if segment == ".." {
            if saw_normal {
                return Err("parent segments are allowed only at the beginning");
            }
            continue;
        }
        saw_normal = true;
        if segment.len() > MAX_PATH_SEGMENT_BYTES {
            return Err("segments must be at most 255 bytes");
        }
        if is_reserved_segment(segment) {
            return Err("must not enter reserved .git or lock paths");
        }
    }
    Ok(())
}

fn validate_git_object_id(value: &str) -> Result<(), &'static str> {
    let hex = if let Some(hex) = value.strip_prefix("sha1-") {
        if hex.len() != 40 {
            return Err("sha1 IDs must contain exactly 40 hexadecimal digits");
        }
        hex
    } else if let Some(hex) = value.strip_prefix("sha256-") {
        if hex.len() != 64 {
            return Err("sha256 IDs must contain exactly 64 hexadecimal digits");
        }
        hex
    } else {
        return Err("must start with sha1- or sha256-");
    };
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("must contain only lowercase hexadecimal digits");
    }
    Ok(())
}

fn canonicalize_https_url(value: &str) -> Result<String, &'static str> {
    if value.len() > MAX_GIT_URL_BYTES {
        return Err("must be at most 2048 bytes");
    }
    if value.trim() != value {
        return Err("must not contain leading or trailing whitespace");
    }
    if value.contains('\\') {
        return Err("must not contain backslashes");
    }
    if contains_control(value) {
        return Err("must not contain control characters");
    }
    let parsed = Url::parse(value).map_err(|_| "must be a valid absolute URL")?;
    if parsed.scheme() != "https" {
        return Err("must use HTTPS");
    }
    if parsed.host_str().is_none() {
        return Err("must contain a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("must not contain embedded credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("must not contain a query or fragment");
    }
    Ok(parsed.to_string())
}

/// A pack location within a Git repository.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PackSubdir {
    /// The repository root, encoded as `.`.
    Root,
    /// A validated pack subdirectory.
    Path(PackPath),
}

impl PackSubdir {
    /// Parses `.` or a pack path.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value == "." {
            Ok(Self::Root)
        } else {
            PackPath::new(value).map(Self::Path)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Root => ".",
            Self::Path(path) => path.as_str(),
        }
    }
}

impl fmt::Display for PackSubdir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for PackSubdir {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PackSubdir {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// An exact Git source accepted by pack/v1.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GitSourceV1 {
    url: GitUrl,
    commit: GitObjectId,
    subdir: PackSubdir,
}

impl GitSourceV1 {
    #[must_use]
    pub const fn new(url: GitUrl, commit: GitObjectId, subdir: PackSubdir) -> Self {
        Self {
            url,
            commit,
            subdir,
        }
    }

    #[must_use]
    pub const fn url(&self) -> &GitUrl {
        &self.url
    }

    #[must_use]
    pub const fn commit(&self) -> &GitObjectId {
        &self.commit
    }

    #[must_use]
    pub const fn subdir(&self) -> &PackSubdir {
        &self.subdir
    }
}

/// A direct dependency source accepted by pack/v1.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DependencySourceV1 {
    /// An exact HTTPS Git source.
    Git(GitSourceV1),
    /// A local source relative to the root pack.
    Local(LocalLocator),
}

/// An exported module and its declaring file.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PackModuleV1 {
    name: ContributionName,
    path: PackPath,
}

impl PackModuleV1 {
    #[must_use]
    pub const fn new(name: ContributionName, path: PackPath) -> Self {
        Self { name, path }
    }

    #[must_use]
    pub const fn name(&self) -> &ContributionName {
        &self.name
    }

    #[must_use]
    pub const fn path(&self) -> &PackPath {
        &self.path
    }
}

/// A direct dependency declaration.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PackDependencyV1 {
    alias: Alias,
    package_id: PackageId,
    source: DependencySourceV1,
}

impl PackDependencyV1 {
    #[must_use]
    pub const fn new(alias: Alias, package_id: PackageId, source: DependencySourceV1) -> Self {
        Self {
            alias,
            package_id,
            source,
        }
    }

    #[must_use]
    pub const fn alias(&self) -> &Alias {
        &self.alias
    }

    #[must_use]
    pub const fn package_id(&self) -> &PackageId {
        &self.package_id
    }

    #[must_use]
    pub const fn source(&self) -> &DependencySourceV1 {
        &self.source
    }
}

/// A component interface accepted by pack/v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ComponentInterfaceV1 {
    /// The import-free `format-component/v1` transform interface.
    FormatComponentV1,
}

impl ComponentInterfaceV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FormatComponentV1 => malm_types::FORMAT_COMPONENT_INTERFACE_V1,
        }
    }
}

/// A component bundled in a pack.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct BundledComponentV1 {
    name: ContributionName,
    path: PackPath,
    digest: Digest,
    interface: ComponentInterfaceV1,
}

impl BundledComponentV1 {
    #[must_use]
    pub const fn new(
        name: ContributionName,
        path: PackPath,
        digest: Digest,
        interface: ComponentInterfaceV1,
    ) -> Self {
        Self {
            name,
            path,
            digest,
            interface,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &ContributionName {
        &self.name
    }

    #[must_use]
    pub const fn path(&self) -> &PackPath {
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
}

/// A semantic pack manifest validation failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PackValidationError {
    #[error("{collection} contains {actual} entries; limit is {limit}")]
    LimitExceeded {
        collection: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("duplicate module {0:?}")]
    DuplicateModule(ContributionName),
    #[error("duplicate dependency alias {0:?}")]
    DuplicateDependencyAlias(Alias),
    #[error("duplicate {collection} path {path:?}")]
    DuplicateResourcePath {
        collection: &'static str,
        path: PackPath,
    },
    #[error("config document path {0:?} is also a module path")]
    ConfigModulePathConflict(PackPath),
    #[error("duplicate component {0:?}")]
    DuplicateComponent(ContributionName),
}

/// A validated pack/v1 manifest independent of KDL encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackManifestV1 {
    package_id: PackageId,
    modules: Vec<PackModuleV1>,
    config_documents: Vec<PackPath>,
    dependencies: Vec<PackDependencyV1>,
    templates: Vec<PackPath>,
    schemas: Vec<PackPath>,
    assets: Vec<PackPath>,
    components: Vec<BundledComponentV1>,
    capture_roots: Vec<PackPath>,
}

impl PackManifestV1 {
    /// Validates and canonicalizes a complete manifest.
    pub fn new(
        package_id: PackageId,
        mut modules: Vec<PackModuleV1>,
        mut dependencies: Vec<PackDependencyV1>,
        mut templates: Vec<PackPath>,
        mut schemas: Vec<PackPath>,
        mut assets: Vec<PackPath>,
        mut components: Vec<BundledComponentV1>,
    ) -> Result<Self, PackValidationError> {
        enforce_limit("modules", modules.len(), MAX_MODULES)?;
        enforce_limit("dependencies", dependencies.len(), MAX_DIRECT_DEPENDENCIES)?;
        enforce_limit("templates", templates.len(), MAX_RESOURCES_PER_KIND)?;
        enforce_limit("schemas", schemas.len(), MAX_RESOURCES_PER_KIND)?;
        enforce_limit("assets", assets.len(), MAX_RESOURCES_PER_KIND)?;
        enforce_limit("components", components.len(), MAX_COMPONENTS)?;

        reject_duplicate_by(&modules, |module| module.name().as_str()).map_err(|name| {
            PackValidationError::DuplicateModule(
                ContributionName::new(name).expect("name came from a validated identifier"),
            )
        })?;
        reject_duplicate_by(&dependencies, |dependency| dependency.alias().as_str()).map_err(
            |alias| {
                PackValidationError::DuplicateDependencyAlias(
                    Alias::new(alias).expect("alias came from a validated identifier"),
                )
            },
        )?;
        reject_duplicate_paths("template", &templates)?;
        reject_duplicate_paths("schema", &schemas)?;
        reject_duplicate_paths("asset", &assets)?;
        reject_duplicate_by(&components, |component| component.name().as_str()).map_err(
            |name| {
                PackValidationError::DuplicateComponent(
                    ContributionName::new(name).expect("name came from a validated identifier"),
                )
            },
        )?;

        modules.sort();
        dependencies.sort();
        templates.sort();
        schemas.sort();
        assets.sort();
        components.sort();

        Ok(Self {
            package_id,
            modules,
            config_documents: vec![],
            dependencies,
            templates,
            schemas,
            assets,
            components,
            capture_roots: vec![],
        })
    }

    /// Restricts local capture to the listed files and directory trees.
    ///
    /// The manifest and lock are always captured. An empty list captures the
    /// entire source root. Verification ignores this list because the content
    /// digest covers the files that were captured.
    pub fn with_capture_roots(
        mut self,
        mut capture_roots: Vec<PackPath>,
    ) -> Result<Self, PackValidationError> {
        enforce_limit("capture roots", capture_roots.len(), MAX_RESOURCES_PER_KIND)?;
        reject_duplicate_paths("capture root", &capture_roots)?;
        capture_roots.sort();
        self.capture_roots = capture_roots;
        Ok(self)
    }

    /// Sets pack documents available to explicit rich includes.
    pub fn with_config_documents(
        mut self,
        mut config_documents: Vec<PackPath>,
    ) -> Result<Self, PackValidationError> {
        enforce_limit(
            "config documents",
            config_documents.len(),
            MAX_RESOURCES_PER_KIND,
        )?;
        reject_duplicate_paths("config document", &config_documents)?;
        let module_paths = self
            .modules
            .iter()
            .map(PackModuleV1::path)
            .collect::<BTreeSet<_>>();
        if let Some(path) = config_documents
            .iter()
            .find(|path| module_paths.contains(path))
        {
            return Err(PackValidationError::ConfigModulePathConflict(path.clone()));
        }
        config_documents.sort();
        self.config_documents = config_documents;
        Ok(self)
    }

    #[must_use]
    pub const fn package_id(&self) -> &PackageId {
        &self.package_id
    }

    /// Returns modules in canonical order.
    #[must_use]
    pub fn modules(&self) -> &[PackModuleV1] {
        &self.modules
    }

    /// Returns documents exported for explicit rich includes.
    #[must_use]
    pub fn config_documents(&self) -> &[PackPath] {
        &self.config_documents
    }

    /// Returns capture roots. An empty slice means capture everything.
    #[must_use]
    pub fn capture_roots(&self) -> &[PackPath] {
        &self.capture_roots
    }

    /// Returns whether a logical pack path is covered by the capture roots.
    ///
    /// Local capture and Git acquisition both narrow through this method, so the
    /// captured file set and its content digest do not depend on the transport.
    /// The manifest is always covered, and no declared root covers everything. A
    /// directory is covered when a root lives beneath it, so a walking adapter
    /// can descend toward a declared subtree.
    #[must_use]
    pub fn covers_capture_path(&self, logical: &str) -> bool {
        if self.capture_roots.is_empty() || logical == PACK_MANIFEST_FILE {
            return true;
        }
        self.capture_roots.iter().any(|root| {
            let root = root.as_str();
            logical == root
                || logical
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('/'))
                || root
                    .strip_prefix(logical)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    /// Returns direct dependencies in alias order.
    #[must_use]
    pub fn dependencies(&self) -> &[PackDependencyV1] {
        &self.dependencies
    }

    #[must_use]
    pub fn templates(&self) -> &[PackPath] {
        &self.templates
    }

    #[must_use]
    pub fn schemas(&self) -> &[PackPath] {
        &self.schemas
    }

    #[must_use]
    pub fn assets(&self) -> &[PackPath] {
        &self.assets
    }

    /// Returns bundled components in name order.
    #[must_use]
    pub fn components(&self) -> &[BundledComponentV1] {
        &self.components
    }
}

fn enforce_limit(
    collection: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), PackValidationError> {
    if actual > limit {
        return Err(PackValidationError::LimitExceeded {
            collection,
            limit,
            actual,
        });
    }
    Ok(())
}

fn reject_duplicate_by<T>(values: &[T], key: impl Fn(&T) -> &str) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for value in values {
        let key = key(value);
        if !seen.insert(key) {
            return Err(key.to_owned());
        }
    }
    Ok(())
}

fn reject_duplicate_paths(
    collection: &'static str,
    paths: &[PackPath],
) -> Result<(), PackValidationError> {
    reject_duplicate_by(paths, PackPath::as_str).map_err(|path| {
        PackValidationError::DuplicateResourcePath {
            collection,
            path: PackPath::new(path).expect("path came from a validated identifier"),
        }
    })
}

/// A pack tree validation or digest failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PackTreeError {
    #[error("pack tree is missing {PACK_MANIFEST_FILE}")]
    MissingManifest,
    #[error("duplicate pack path {0:?}")]
    DuplicatePath(PackPath),
    #[error("pack tree contains {actual} entries; limit is {limit}")]
    TooManyEntries {
        limit: usize,
        actual: usize,
    },
    #[error("pack file {path:?} is {actual} bytes; limit is {limit}")]
    FileTooLarge {
        path: PackPath,
        limit: u64,
        actual: u64,
    },
    #[error("pack tree is {actual} bytes; limit is {limit}")]
    TreeTooLarge {
        limit: u64,
        actual: u64,
    },
}

/// Applies the pack/v1 source-tree exclusions to a path.
///
/// Paths containing `.git`, `malm.lock`, or `.malm-lock.tmp` return `Ok(None)`
/// and must not enter a pack object. Other paths are validated normally.
pub fn classify_pack_tree_path(value: impl Into<String>) -> Result<Option<PackPath>, ValueError> {
    let value = value.into();
    if value.split('/').any(is_reserved_segment) {
        return Ok(None);
    }
    PackPath::new(value).map(Some)
}

/// Domain separator for canonical pack content.
pub(crate) const PACK_CONTENT_DOMAIN: &[u8] = b"malm-pack-content\0";

/// Encodes the framing shared by the tree digest and pack object.
///
/// The format is an entry count followed by a length-prefixed path and
/// length-prefixed contents for each entry.
pub(crate) fn encode_pack_entries(encoder: &mut Encoder<'_>, entries: &[(&PackPath, &[u8])]) {
    encoder.u64(malm_types::usize_to_u64(entries.len()));
    for (path, bytes) in entries {
        encoder.text(path.as_str());
        encoder.bytes(bytes);
    }
}

/// Computes the canonical digest of a complete pack tree.
///
/// Callers must supply every included file. Files are sorted by UTF-8 path
/// bytes. Filesystem metadata and empty directories are not included.
pub fn pack_content_digest<'a, I>(entries: I) -> Result<Digest, PackTreeError>
where
    I: IntoIterator<Item = (&'a PackPath, &'a [u8])>,
{
    let entries = validated_pack_entries(entries)?;
    let mut encoder = Encoder::new(PACK_CONTENT_DOMAIN);
    encode_pack_entries(&mut encoder, &entries);
    Ok(encoder.finish())
}

pub(crate) fn validated_pack_entries<'a, I>(
    entries: I,
) -> Result<Vec<(&'a PackPath, &'a [u8])>, PackTreeError>
where
    I: IntoIterator<Item = (&'a PackPath, &'a [u8])>,
{
    let mut entries = entries
        .into_iter()
        .take(MAX_PACK_TREE_ENTRIES + 1)
        .collect::<Vec<_>>();
    if entries.len() > MAX_PACK_TREE_ENTRIES {
        return Err(PackTreeError::TooManyEntries {
            limit: MAX_PACK_TREE_ENTRIES,
            actual: entries.len(),
        });
    }
    entries.sort_by(|left, right| left.0.cmp(right.0));

    let mut previous: Option<&PackPath> = None;
    let mut total = 0_u64;
    let mut found_manifest = false;
    for (path, bytes) in &entries {
        if previous == Some(path) {
            return Err(PackTreeError::DuplicatePath((*path).clone()));
        }
        previous = Some(path);
        found_manifest |= path.as_str() == PACK_MANIFEST_FILE;

        let length = malm_types::usize_to_u64(bytes.len());
        if length > MAX_PACK_FILE_BYTES {
            return Err(PackTreeError::FileTooLarge {
                path: (*path).clone(),
                limit: MAX_PACK_FILE_BYTES,
                actual: length,
            });
        }
        total = total.saturating_add(length);
        if total > MAX_PACK_TREE_BYTES {
            return Err(PackTreeError::TreeTooLarge {
                limit: MAX_PACK_TREE_BYTES,
                actual: total,
            });
        }
    }
    if !found_manifest {
        return Err(PackTreeError::MissingManifest);
    }

    Ok(entries)
}
