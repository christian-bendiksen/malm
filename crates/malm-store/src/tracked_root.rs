use crate::DEFAULT_HISTORY_RETENTION_GENERATIONS;
use crate::MAX_ACQUISITION_GRANT_LOCATOR_BYTES;
use crate::MAX_EXPLICIT_PINS;
use crate::MAX_HISTORY_RETENTION_GENERATIONS;
use crate::MAX_RESTORE_POINTS;
use crate::MAX_TRACKED_ROOT_ACQUISITION_BYTES;
use crate::MAX_TRACKED_ROOT_ACQUISITION_GRANTS;
use crate::MAX_TRACKED_ROOT_CONFIG_ENTRY_POINT_BYTES;
use crate::MAX_TRACKED_ROOT_MOVING_SELECTOR_BYTES;
use crate::MAX_TRACKED_ROOT_SOURCE_LOCATOR_BYTES;
use crate::MAX_TRACKED_ROOT_SOURCE_SUBDIR_BYTES;
use crate::PREPARED_RECORD_SCHEMA_VERSION;
use crate::TRACKED_ROOT_SCHEMA_VERSION;
use crate::bounded_seq_eager;
use crate::prepared::PreparedRecordError;
use crate::validate::check_limit;
use crate::validate::reject_duplicates;
use crate::validate::validate_text;
use malm_types::ContributionName;
use malm_types::DeploymentName;
use malm_types::Digest;
use malm_types::NamespaceName;
use malm_types::RetentionObjectV1;
use serde::Deserialize;
use serde::Serialize;

/// Schema versions bound to a prepared plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaVersionsV1 {
    pub store: u32,
    pub config: u32,
    pub pack: u32,
    pub lock: u32,
    pub format_component: u32,
}

impl Default for SchemaVersionsV1 {
    fn default() -> Self {
        Self {
            store: PREPARED_RECORD_SCHEMA_VERSION,
            config: 1,
            pack: 1,
            lock: 1,
            format_component: 1,
        }
    }
}

/// Controls whether a selected namespace generation owns its snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleStateV1 {
    #[default]
    Enabled,
    Disabled,
}

impl LifecycleStateV1 {
    /// Reports whether the selected generation contributes ownership claims.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

malm_types::validated_string! {
    /// A canonical HTTPS locator for a tracked-root source that may move.
    pub struct TrackedRootSourceLocatorV1;
    error: PreparedRecordError;
    validate: |value: &str| validate_tracked_root_source_locator(value);
    make_error: |_value, reason| reason;
    impl: serde, from_string;
}

malm_types::validated_string! {
    /// A canonical symbolic selector resolved during tracked-root preparation.
    pub struct MovingSelectorV1;
    error: PreparedRecordError;
    validate: |value: &str| validate_moving_selector(value);
    make_error: |_value, reason| reason;
    impl: serde, from_string;
}

malm_types::validated_string! {
    /// A full algorithm-tagged immutable revision selected during preparation.
    pub struct ExactRevisionV1;
    error: PreparedRecordError;
    validate: |value: &str| validate_exact_revision(value);
    make_error: |_value, reason| reason;
    impl: serde, from_string;
}

malm_types::validated_string! {
    /// The canonical pack root selected inside a tracked Git repository.
    pub struct TrackedRootSubdirV1;
    error: PreparedRecordError;
    validate: |value: &str| validate_tracked_root_subdir(value);
    make_error: |_value, reason| reason;
    impl: serde, from_string;
}

impl TrackedRootSubdirV1 {
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.as_str() == "."
    }
}

impl Default for TrackedRootSubdirV1 {
    fn default() -> Self {
        Self(".".to_owned())
    }
}

malm_types::validated_string! {
    /// A canonical config file path relative to the tracked root tree.
    pub struct ConfigEntryPointV1;
    error: PreparedRecordError;
    validate: |value: &str| validate_config_entry_point(value);
    make_error: |_value, reason| reason;
    impl: serde, from_string;
}

malm_types::validated_string! {
    /// Canonical locator text interpreted according to an acquisition-grant kind.
    pub struct AcquisitionGrantLocatorV1;
    error: PreparedRecordError;
    validate: |value: &str| validate_acquisition_grant_locator_text(value);
    make_error: |_value, reason| reason;
    impl: serde, from_string;
}

/// The closed authority kinds persisted for later tracked-root acquisition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionGrantKindV1 {
    LocalSource,
    GitSource,
    FormatComponent,
    TargetAuthority,
}

/// A persisted acquisition authority with an exact locator.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionGrantV1 {
    kind: AcquisitionGrantKindV1,
    locator: AcquisitionGrantLocatorV1,
}

impl AcquisitionGrantV1 {
    /// Creates a grant and validates its locator for the selected authority kind.
    pub fn new(
        kind: AcquisitionGrantKindV1,
        locator: impl Into<String>,
    ) -> Result<Self, PreparedRecordError> {
        let grant = Self {
            kind,
            locator: AcquisitionGrantLocatorV1::new(locator)?,
        };
        validate_acquisition_grant(&grant)?;
        Ok(grant)
    }

    #[must_use]
    pub const fn kind(&self) -> AcquisitionGrantKindV1 {
        self.kind
    }
    #[must_use]
    pub const fn locator(&self) -> &AcquisitionGrantLocatorV1 {
        &self.locator
    }
}

/// Complete immutable update authority and last-applied identity for a tracked root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackedRootV1 {
    pub(crate) schema_version: u32,
    pub(crate) source_locator: TrackedRootSourceLocatorV1,
    pub(crate) moving_selector: MovingSelectorV1,
    pub(crate) applied_revision: ExactRevisionV1,
    pub(crate) root_tree_digest: Digest,
    #[serde(default, skip_serializing_if = "TrackedRootSubdirV1::is_root")]
    pub(crate) source_subdir: TrackedRootSubdirV1,
    pub(crate) config_entry_point: ConfigEntryPointV1,
    pub(crate) selected_profile: ContributionName,
    #[serde(deserialize_with = "deserialize_acquisition_grants")]
    pub(crate) acquisition_grants: Vec<AcquisitionGrantV1>,
}

impl TrackedRootV1 {
    /// Creates a canonical tracked-root record, sorting and deduplicating grants.
    pub fn new(
        source_locator: TrackedRootSourceLocatorV1,
        moving_selector: MovingSelectorV1,
        applied_revision: ExactRevisionV1,
        root_tree_digest: Digest,
        config_entry_point: ConfigEntryPointV1,
        selected_profile: ContributionName,
        mut acquisition_grants: Vec<AcquisitionGrantV1>,
    ) -> Result<Self, PreparedRecordError> {
        check_limit(
            "tracked-root acquisition grants",
            acquisition_grants.len(),
            MAX_TRACKED_ROOT_ACQUISITION_GRANTS,
        )?;
        for grant in &acquisition_grants {
            validate_acquisition_grant(grant)?;
        }
        acquisition_grants.sort();
        reject_duplicates("tracked-root acquisition grant", acquisition_grants.iter())?;
        let tracked_root = Self {
            schema_version: TRACKED_ROOT_SCHEMA_VERSION,
            source_locator,
            moving_selector,
            applied_revision,
            root_tree_digest,
            source_subdir: TrackedRootSubdirV1::default(),
            config_entry_point,
            selected_profile,
            acquisition_grants,
        };
        validate_tracked_root(&tracked_root)?;
        Ok(tracked_root)
    }

    /// Selects a non-default canonical pack root inside the source repository.
    pub fn with_source_subdir(
        mut self,
        source_subdir: TrackedRootSubdirV1,
    ) -> Result<Self, PreparedRecordError> {
        validate_tracked_root_subdir(source_subdir.as_str())?;
        self.source_subdir = source_subdir;
        validate_tracked_root(&self)?;
        Ok(self)
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    #[must_use]
    pub const fn source_locator(&self) -> &TrackedRootSourceLocatorV1 {
        &self.source_locator
    }
    #[must_use]
    pub const fn moving_selector(&self) -> &MovingSelectorV1 {
        &self.moving_selector
    }
    #[must_use]
    pub const fn applied_revision(&self) -> &ExactRevisionV1 {
        &self.applied_revision
    }
    #[must_use]
    pub const fn root_tree_digest(&self) -> &Digest {
        &self.root_tree_digest
    }
    #[must_use]
    pub const fn source_subdir(&self) -> &TrackedRootSubdirV1 {
        &self.source_subdir
    }
    #[must_use]
    pub const fn config_entry_point(&self) -> &ConfigEntryPointV1 {
        &self.config_entry_point
    }
    #[must_use]
    pub const fn selected_profile(&self) -> &ContributionName {
        &self.selected_profile
    }
    #[must_use]
    pub fn acquisition_grants(&self) -> &[AcquisitionGrantV1] {
        &self.acquisition_grants
    }

    /// Replaces only the selected profile while preserving all acquisition authority.
    pub fn with_selected_profile(
        mut self,
        selected_profile: ContributionName,
    ) -> Result<Self, PreparedRecordError> {
        self.selected_profile = selected_profile;
        validate_tracked_root(&self)?;
        Ok(self)
    }
}

/// Bounded predecessor retention selected for a namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRetentionPolicyV1 {
    generations: u32,
}

impl HistoryRetentionPolicyV1 {
    pub fn new(generations: u32) -> Result<Self, PreparedRecordError> {
        if generations == 0 || generations > MAX_HISTORY_RETENTION_GENERATIONS {
            return Err(PreparedRecordError::InvalidField {
                field: "history retention generations",
                reason: "must be in 1..=65536",
            });
        }
        Ok(Self { generations })
    }

    #[must_use]
    pub const fn generations(self) -> u32 {
        self.generations
    }
}

impl Default for HistoryRetentionPolicyV1 {
    fn default() -> Self {
        Self {
            generations: DEFAULT_HISTORY_RETENTION_GENERATIONS,
        }
    }
}

/// Immutable exact state selected as lifecycle or user restore authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePointV1 {
    namespace: NamespaceName,
    generation: Digest,
    lifecycle: LifecycleStateV1,
    desired_snapshot_digest: Digest,
    tracked_root: Option<TrackedRootV1>,
}

impl RestorePointV1 {
    #[must_use]
    pub fn new(
        namespace: NamespaceName,
        generation: Digest,
        lifecycle: LifecycleStateV1,
        desired_snapshot_digest: Digest,
        tracked_root: Option<TrackedRootV1>,
    ) -> Self {
        Self {
            namespace,
            generation,
            lifecycle,
            desired_snapshot_digest,
            tracked_root,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
    #[must_use]
    pub const fn generation(&self) -> &Digest {
        &self.generation
    }
    #[must_use]
    pub const fn lifecycle(&self) -> LifecycleStateV1 {
        self.lifecycle
    }
    #[must_use]
    pub const fn desired_snapshot_digest(&self) -> &Digest {
        &self.desired_snapshot_digest
    }
    #[must_use]
    pub const fn tracked_root(&self) -> Option<&TrackedRootV1> {
        self.tracked_root.as_ref()
    }
}

/// Complete immutable retention authority copied through namespace generations.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionAuthorityV1 {
    history: HistoryRetentionPolicyV1,
    #[serde(deserialize_with = "deserialize_restore_points")]
    restore_points: Vec<RestorePointV1>,
    #[serde(deserialize_with = "deserialize_explicit_pins")]
    explicit_pins: Vec<RetentionObjectV1>,
}

impl RetentionAuthorityV1 {
    pub fn new(
        history: HistoryRetentionPolicyV1,
        mut restore_points: Vec<RestorePointV1>,
        mut explicit_pins: Vec<RetentionObjectV1>,
    ) -> Result<Self, PreparedRecordError> {
        check_limit("restore points", restore_points.len(), MAX_RESTORE_POINTS)?;
        check_limit("explicit pins", explicit_pins.len(), MAX_EXPLICIT_PINS)?;
        restore_points.sort_by(|left, right| left.generation.cmp(&right.generation));
        reject_duplicates(
            "restore point generation",
            restore_points.iter().map(|point| &point.generation),
        )?;
        explicit_pins.sort();
        reject_duplicates("explicit pin", explicit_pins.iter())?;
        let authority = Self {
            history,
            restore_points,
            explicit_pins,
        };
        validate_retention_authority(&authority, None)?;
        Ok(authority)
    }

    #[must_use]
    pub const fn history(&self) -> HistoryRetentionPolicyV1 {
        self.history
    }
    #[must_use]
    pub fn restore_points(&self) -> &[RestorePointV1] {
        &self.restore_points
    }
    #[must_use]
    pub fn explicit_pins(&self) -> &[RetentionObjectV1] {
        &self.explicit_pins
    }

    pub fn with_history(
        mut self,
        history: HistoryRetentionPolicyV1,
    ) -> Result<Self, PreparedRecordError> {
        self.history = history;
        validate_retention_authority(&self, None)?;
        Ok(self)
    }

    pub fn with_restore_point(
        mut self,
        restore_point: RestorePointV1,
    ) -> Result<Self, PreparedRecordError> {
        match self
            .restore_points
            .binary_search_by(|point| point.generation.cmp(&restore_point.generation))
        {
            Ok(index) => self.restore_points[index] = restore_point,
            Err(index) => self.restore_points.insert(index, restore_point),
        }
        check_limit(
            "restore points",
            self.restore_points.len(),
            MAX_RESTORE_POINTS,
        )?;
        validate_retention_authority(&self, None)?;
        Ok(self)
    }

    pub fn without_restore_point(
        mut self,
        generation: &Digest,
    ) -> Result<Self, PreparedRecordError> {
        let index = self
            .restore_points
            .binary_search_by(|point| point.generation.cmp(generation))
            .map_err(|_| PreparedRecordError::InvalidField {
                field: "restore point",
                reason: "the selected generation is not an explicit restore point",
            })?;
        self.restore_points.remove(index);
        Ok(self)
    }

    pub fn with_pin(mut self, pin: RetentionObjectV1) -> Result<Self, PreparedRecordError> {
        match self.explicit_pins.binary_search(&pin) {
            Ok(_) => {
                return Err(PreparedRecordError::InvalidField {
                    field: "explicit pin",
                    reason: "the selected object is already pinned",
                });
            }
            Err(index) => self.explicit_pins.insert(index, pin),
        }
        check_limit("explicit pins", self.explicit_pins.len(), MAX_EXPLICIT_PINS)?;
        Ok(self)
    }

    pub fn without_pin(mut self, pin: &RetentionObjectV1) -> Result<Self, PreparedRecordError> {
        let index = self.explicit_pins.binary_search(pin).map_err(|_| {
            PreparedRecordError::InvalidField {
                field: "explicit pin",
                reason: "the selected object is not pinned",
            }
        })?;
        self.explicit_pins.remove(index);
        Ok(self)
    }
}

/// The namespace-history disposition approved for catalog removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NamespaceRemovalHistoryV1 {
    Drop,
}

/// The closed transition kinds bound to an immutable prepared record.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PreparedTransitionV1 {
    #[default]
    Reconcile,
    Disable,
    Enable {
        restore_point: Box<RestorePointV1>,
    },
    Checkout {
        source_generation: Digest,
    },
    RetentionAuthority,
    NamespaceRemoval {
        history: NamespaceRemovalHistoryV1,
    },
}

pub(crate) fn validate_restore_point(
    point: &RestorePointV1,
    namespace: Option<&NamespaceName>,
) -> Result<(), PreparedRecordError> {
    if namespace.is_some_and(|namespace| namespace != point.namespace()) {
        return Err(PreparedRecordError::InvalidField {
            field: "restore point namespace",
            reason: "must match the prepared namespace",
        });
    }
    if let Some(tracked_root) = point.tracked_root() {
        validate_tracked_root(tracked_root)?;
    }
    Ok(())
}

pub(crate) fn validate_retention_authority(
    authority: &RetentionAuthorityV1,
    namespace: Option<&NamespaceName>,
) -> Result<(), PreparedRecordError> {
    HistoryRetentionPolicyV1::new(authority.history.generations)?;
    check_limit(
        "restore points",
        authority.restore_points.len(),
        MAX_RESTORE_POINTS,
    )?;
    check_limit(
        "explicit pins",
        authority.explicit_pins.len(),
        MAX_EXPLICIT_PINS,
    )?;
    for point in &authority.restore_points {
        validate_restore_point(point, namespace)?;
    }
    for pair in authority.restore_points.windows(2) {
        if pair[0].generation >= pair[1].generation {
            return Err(PreparedRecordError::InvalidField {
                field: "restore points",
                reason: "must be strictly ordered by generation",
            });
        }
    }
    for pair in authority.explicit_pins.windows(2) {
        if pair[0] >= pair[1] {
            return Err(PreparedRecordError::InvalidField {
                field: "explicit pins",
                reason: "must be strictly ordered",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_selected_restore_authority(
    lifecycle: LifecycleStateV1,
    selected: Option<&RestorePointV1>,
    authority: &RetentionAuthorityV1,
) -> Result<(), PreparedRecordError> {
    match (lifecycle, selected) {
        (LifecycleStateV1::Enabled, None) => Ok(()),
        (LifecycleStateV1::Enabled, Some(_)) => Err(PreparedRecordError::InvalidField {
            field: "selected restore point",
            reason: "an enabled generation cannot select a restore point",
        }),
        (LifecycleStateV1::Disabled, None) => Err(PreparedRecordError::InvalidField {
            field: "selected restore point",
            reason: "a disabled generation must select a restore point",
        }),
        (LifecycleStateV1::Disabled, Some(point))
            if !authority.restore_points().contains(point) =>
        {
            Err(PreparedRecordError::InvalidField {
                field: "selected restore point",
                reason: "must be included exactly in the generation retention authority",
            })
        }
        (LifecycleStateV1::Disabled, Some(_)) => Ok(()),
    }
}

fn deserialize_restore_points<'de, D>(deserializer: D) -> Result<Vec<RestorePointV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_seq_eager(
        deserializer,
        MAX_RESTORE_POINTS,
        "restore points",
        "retention authority",
        "restore points",
    )
}

fn deserialize_explicit_pins<'de, D>(deserializer: D) -> Result<Vec<RetentionObjectV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_seq_eager(
        deserializer,
        MAX_EXPLICIT_PINS,
        "explicit pins",
        "retention authority",
        "explicit pins",
    )
}

pub(crate) fn validate_tracked_root(
    tracked_root: &TrackedRootV1,
) -> Result<(), PreparedRecordError> {
    if tracked_root.schema_version != TRACKED_ROOT_SCHEMA_VERSION {
        return Err(PreparedRecordError::UnsupportedVersion {
            expected: TRACKED_ROOT_SCHEMA_VERSION,
            found: tracked_root.schema_version,
        });
    }
    check_limit(
        "tracked-root acquisition grants",
        tracked_root.acquisition_grants.len(),
        MAX_TRACKED_ROOT_ACQUISITION_GRANTS,
    )?;

    let mut aggregate_bytes = 0_usize;
    for grant in &tracked_root.acquisition_grants {
        validate_acquisition_grant(grant)?;
        aggregate_bytes = aggregate_bytes
            .checked_add(grant.locator.as_str().len())
            .ok_or(PreparedRecordError::InvalidField {
                field: "tracked-root acquisition grants",
                reason: "aggregate locator bytes overflow",
            })?;
    }
    check_limit(
        "tracked-root acquisition grant bytes",
        aggregate_bytes,
        MAX_TRACKED_ROOT_ACQUISITION_BYTES,
    )?;
    for pair in tracked_root.acquisition_grants.windows(2) {
        match pair[0].cmp(&pair[1]) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(PreparedRecordError::Duplicate {
                    field: "tracked-root acquisition grant",
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(PreparedRecordError::InvalidField {
                    field: "tracked-root acquisition grants",
                    reason: "must be strictly sorted by kind and locator",
                });
            }
        }
    }
    Ok(())
}

fn validate_tracked_root_source_locator(value: &str) -> Result<(), PreparedRecordError> {
    validate_canonical_https_locator(
        "tracked-root source locator",
        value,
        MAX_TRACKED_ROOT_SOURCE_LOCATOR_BYTES,
    )
}

fn validate_moving_selector(value: &str) -> Result<(), PreparedRecordError> {
    validate_text(
        "tracked-root moving selector",
        value,
        MAX_TRACKED_ROOT_MOVING_SELECTOR_BYTES,
    )?;
    if value.trim() != value
        || value == "@"
        || value.starts_with('/')
        || value.ends_with('/')
        || value.ends_with('.')
        || value.contains("//")
        || value.contains("..")
        || value.contains("@{")
        || value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value
            .bytes()
            .any(|byte| matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'['))
        || value
            .split('/')
            .any(|component| component.starts_with('.') || component.ends_with(".lock"))
        || looks_like_exact_revision(value)
        || looks_like_untagged_revision(value)
    {
        return Err(PreparedRecordError::InvalidField {
            field: "tracked-root moving selector",
            reason: "must be a bounded canonical symbolic Git selector",
        });
    }
    Ok(())
}

fn validate_exact_revision(value: &str) -> Result<(), PreparedRecordError> {
    if !looks_like_exact_revision(value) {
        return Err(PreparedRecordError::InvalidField {
            field: "tracked-root applied revision",
            reason: "must be sha1- plus 40 or sha256- plus 64 lowercase hexadecimal digits",
        });
    }
    Ok(())
}

fn validate_tracked_root_subdir(value: &str) -> Result<(), PreparedRecordError> {
    if value == "." {
        return Ok(());
    }
    validate_text(
        "tracked-root source subdirectory",
        value,
        MAX_TRACKED_ROOT_SOURCE_SUBDIR_BYTES,
    )?;
    if value.starts_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || value.split('/').count() > 32
        || value.split('/').any(|segment| {
            segment.is_empty()
                || matches!(
                    segment,
                    "." | ".." | ".git" | "malm.lock" | ".malm-lock.tmp"
                )
                || segment.len() > 255
        })
    {
        return Err(PreparedRecordError::InvalidField {
            field: "tracked-root source subdirectory",
            reason: "must be dot or a bounded canonical repository-relative path",
        });
    }
    Ok(())
}

fn looks_like_exact_revision(value: &str) -> bool {
    let hexadecimal = if let Some(value) = value.strip_prefix("sha1-") {
        if value.len() != 40 {
            return false;
        }
        value
    } else if let Some(value) = value.strip_prefix("sha256-") {
        if value.len() != 64 {
            return false;
        }
        value
    } else {
        return false;
    };
    hexadecimal
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn looks_like_untagged_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_config_entry_point(value: &str) -> Result<(), PreparedRecordError> {
    validate_text(
        "tracked-root config entry point",
        value,
        MAX_TRACKED_ROOT_CONFIG_ENTRY_POINT_BYTES,
    )?;
    if value.starts_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || value.split('/').count() > 32
        || value.split('/').any(|segment| {
            segment.is_empty()
                || matches!(
                    segment,
                    "." | ".." | ".git" | "malm.lock" | ".malm-lock.tmp"
                )
                || segment.len() > 255
        })
    {
        return Err(PreparedRecordError::InvalidField {
            field: "tracked-root config entry point",
            reason: "must be a bounded canonical root-relative file path",
        });
    }
    Ok(())
}

fn validate_acquisition_grant_locator_text(value: &str) -> Result<(), PreparedRecordError> {
    validate_text(
        "acquisition grant locator",
        value,
        MAX_ACQUISITION_GRANT_LOCATOR_BYTES,
    )?;
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(PreparedRecordError::InvalidField {
            field: "acquisition grant locator",
            reason: "must not contain surrounding whitespace or control characters",
        });
    }
    Ok(())
}

fn validate_acquisition_grant(grant: &AcquisitionGrantV1) -> Result<(), PreparedRecordError> {
    match grant.kind {
        AcquisitionGrantKindV1::LocalSource => {
            validate_local_acquisition_locator(grant.locator.as_str())
        }
        AcquisitionGrantKindV1::GitSource => validate_canonical_https_locator(
            "Git acquisition grant locator",
            grant.locator.as_str(),
            MAX_ACQUISITION_GRANT_LOCATOR_BYTES,
        ),
        AcquisitionGrantKindV1::FormatComponent => {
            Digest::new(grant.locator.as_str()).map_err(|_| PreparedRecordError::InvalidField {
                field: "format component acquisition grant locator",
                reason: "must be a full canonical SHA-256 digest",
            })?;
            Ok(())
        }
        AcquisitionGrantKindV1::TargetAuthority => {
            DeploymentName::new(grant.locator.as_str()).map_err(|_| {
                PreparedRecordError::InvalidField {
                    field: "target authority acquisition grant locator",
                    reason: "must be a valid deployment authority name",
                }
            })?;
            Ok(())
        }
    }
}

fn validate_local_acquisition_locator(value: &str) -> Result<(), PreparedRecordError> {
    if value == "." {
        return Ok(());
    }
    validate_text(
        "local acquisition grant locator",
        value,
        MAX_ACQUISITION_GRANT_LOCATOR_BYTES,
    )?;
    let mut saw_normal = false;
    if value.starts_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || value.split('/').count() > 64
    {
        return Err(PreparedRecordError::InvalidField {
            field: "local acquisition grant locator",
            reason: "must be a bounded canonical root-relative local locator",
        });
    }
    for segment in value.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment.len() > 255
            || matches!(segment, ".git" | "malm.lock" | ".malm-lock.tmp")
            || (segment == ".." && saw_normal)
        {
            return Err(PreparedRecordError::InvalidField {
                field: "local acquisition grant locator",
                reason: "must be a bounded canonical root-relative local locator",
            });
        }
        if segment != ".." {
            saw_normal = true;
        }
    }
    Ok(())
}

fn validate_canonical_https_locator(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), PreparedRecordError> {
    validate_text(field, value, limit)?;
    let Some(remainder) = value.strip_prefix("https://") else {
        return Err(PreparedRecordError::InvalidField {
            field,
            reason: "must be a canonical credential-free HTTPS locator",
        });
    };
    let Some((authority, path)) = remainder.split_once('/') else {
        return Err(PreparedRecordError::InvalidField {
            field,
            reason: "must be a canonical credential-free HTTPS locator",
        });
    };
    if value.trim() != value
        || !value.is_ascii()
        || value.chars().any(char::is_control)
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || authority.is_empty()
        || authority.contains('@')
        || authority.bytes().any(|byte| byte.is_ascii_uppercase())
        || !is_canonical_https_authority(authority)
        || !is_canonical_url_path(path)
    {
        return Err(PreparedRecordError::InvalidField {
            field,
            reason: "must be a canonical credential-free HTTPS locator",
        });
    }
    Ok(())
}

fn is_canonical_https_authority(authority: &str) -> bool {
    let port = if let Some(authority) = authority.strip_prefix('[') {
        let Some((host, remainder)) = authority.split_once(']') else {
            return false;
        };
        if host.is_empty()
            || !host.contains(':')
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
        {
            return false;
        }
        if remainder.is_empty() {
            None
        } else if let Some(port) = remainder.strip_prefix(':') {
            Some(port)
        } else {
            return false;
        }
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if host.is_empty()
            || host.starts_with('.')
            || host.ends_with('.')
            || host.contains("..")
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return false;
        }
        port
    };
    port.is_none_or(|port| {
        !port.is_empty()
            && !port.starts_with('0')
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port
                .parse::<u16>()
                .is_ok_and(|port| port != 0 && port != 443)
    })
}

fn is_canonical_url_path(path: &str) -> bool {
    if path.split('/').any(|segment| matches!(segment, "." | "..")) {
        return false;
    }
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(hexadecimal) = bytes.get(index + 1..index + 3) else {
                return false;
            };
            if !hexadecimal
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
            {
                return false;
            }
            index += 3;
        } else {
            if matches!(
                bytes[index],
                b'"' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'|'
            ) {
                return false;
            }
            index += 1;
        }
    }
    true
}

fn deserialize_acquisition_grants<'de, D>(
    deserializer: D,
) -> Result<Vec<AcquisitionGrantV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_seq_eager(
        deserializer,
        MAX_TRACKED_ROOT_ACQUISITION_GRANTS,
        "tracked-root acquisition grants",
        "tracked root",
        "acquisition grants",
    )
}

#[cfg(test)]
mod tests;
