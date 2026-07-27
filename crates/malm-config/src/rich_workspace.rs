use std::collections::{BTreeMap, BTreeSet};

use malm_pack::PackPath;
use malm_types::{Alias, Digest};

use crate::rich::{
    CapturedAuthorityGraphV1, CapturedConfigDocumentV1, CapturedDocumentIdV1,
    CapturedDocumentSetV1, CapturedIncludeV1, DocumentAuthorityV1, RichConfigErrorV1,
    RichDiagnosticLocationV1, RichDiagnosticSeverityV1, RichDiagnosticV1, RichIncludeReferenceV1,
    RichModuleReferenceV1, RichNameV1, RichStatementV1, SourceLocationV1, SourceRangeV1,
    insert_unique, insert_unique_key,
};
use crate::rich_eval::{
    LocatedRichStatementV1, RichEvaluationErrorV1, RichEvaluationV1,
    evaluate_rich_config_with_statements_v1, reachable_rich_document_order_v1,
};
use crate::{
    MAX_RICH_OUTPUTS, MAX_RICH_PROFILE_DEPTH, MAX_RICH_PROFILE_PARENTS, MAX_RICH_PROFILES,
    MAX_RICH_SLOT_PROVIDERS, MAX_RICH_SLOTS, MAX_RICH_STATEMENTS, MAX_TARGET_PATH_BYTES,
    MAX_TARGET_PATH_SEGMENTS, MAX_TRANSFORM_OPTIONS, MAX_TRANSFORM_RESOURCES, TargetPathV1,
    TransformOptionV1, TypedValueV1,
};

malm_types::validated_string! {
    /// A relative symlink target that cannot escape through lexical dot segments.
    pub struct SafeRelativeSymlinkV1;
    error: RichConfigErrorV1;
    // The validator already returns the public error. The rejected value is
    // unused, and the error passes through unchanged.
    validate: validate_safe_symlink;
    make_error: |_value, reason| reason;
}

fn validate_safe_symlink(value: &str) -> Result<(), RichConfigErrorV1> {
    if value.is_empty() {
        return Err(RichConfigErrorV1::InvalidValue {
            reason: "safe relative symlink target must not be empty",
        });
    }
    if value.len() > MAX_TARGET_PATH_BYTES {
        return Err(RichConfigErrorV1::LimitExceeded {
            resource: "safe relative symlink target bytes",
            limit: MAX_TARGET_PATH_BYTES,
            actual: value.len(),
        });
    }
    if value.starts_with('/') || value.contains('\\') {
        return Err(RichConfigErrorV1::InvalidValue {
            reason: "safe symlink target must be relative and use slash separators",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(RichConfigErrorV1::InvalidValue {
            reason: "safe symlink target must not contain control characters",
        });
    }
    let segments = value.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_TARGET_PATH_SEGMENTS {
        return Err(RichConfigErrorV1::LimitExceeded {
            resource: "safe relative symlink target segments",
            limit: MAX_TARGET_PATH_SEGMENTS,
            actual: segments.len(),
        });
    }
    if segments
        .iter()
        .any(|segment| segment.is_empty() || matches!(*segment, "." | "..") || segment.len() > 255)
    {
        return Err(RichConfigErrorV1::InvalidValue {
            reason: "safe symlink target contains an empty, dot, or overlong segment",
        });
    }
    Ok(())
}

/// The closed set of standard format transforms implemented by `malm-config`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BuiltInFormatTransformV1 {
    CanonicalJson,
    PlainText,
    KeyValue,
}

impl BuiltInFormatTransformV1 {
    pub fn parse(value: &str) -> Result<Self, RichConfigErrorV1> {
        match value {
            "canonical-json" => Ok(Self::CanonicalJson),
            "plain-text" => Ok(Self::PlainText),
            "key-value" => Ok(Self::KeyValue),
            _ => Err(RichConfigErrorV1::InvalidValue {
                reason: "unknown built-in format transform",
            }),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalJson => "canonical-json",
            Self::PlainText => "plain-text",
            Self::KeyValue => "key-value",
        }
    }
}

/// The exact implementation selected by a transformed rich file declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FormatTransformSelectionV1 {
    BuiltIn(BuiltInFormatTransformV1),
    Component {
        name: RichNameV1,
        component_digest: Digest,
    },
}

/// A manifest resource kind that authorizes exact pack-backed bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackResourceKindV1 {
    Asset,
    Template,
    Schema,
}

impl PackResourceKindV1 {
    pub fn parse(value: &str) -> Result<Self, RichConfigErrorV1> {
        match value {
            "asset" => Ok(Self::Asset),
            "template" => Ok(Self::Template),
            "schema" => Ok(Self::Schema),
            _ => Err(RichConfigErrorV1::InvalidValue {
                reason: "unknown pack resource kind",
            }),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asset => "asset",
            Self::Template => "template",
            Self::Schema => "schema",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RichPackFileReferenceV1 {
    pub(crate) dependency: Option<Alias>,
    pub(crate) path: PackPath,
    pub(crate) kind: PackResourceKindV1,
    pub(crate) raw_digest: Digest,
    pub(crate) object_digest: Digest,
    pub(crate) byte_len: u64,
}

/// An exact locked-pack byte identity selected by rich evaluation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CapturedPackFileReferenceV1 {
    authority: DocumentAuthorityV1,
    path: PackPath,
    kind: PackResourceKindV1,
    raw_digest: Digest,
    object_digest: Digest,
    byte_len: u64,
}

impl CapturedPackFileReferenceV1 {
    #[must_use]
    pub const fn authority(&self) -> &DocumentAuthorityV1 {
        &self.authority
    }
    #[must_use]
    pub const fn path(&self) -> &PackPath {
        &self.path
    }
    #[must_use]
    pub const fn kind(&self) -> PackResourceKindV1 {
        self.kind
    }
    #[must_use]
    pub const fn raw_digest(&self) -> &Digest {
        &self.raw_digest
    }
    #[must_use]
    pub const fn object_digest(&self) -> &Digest {
        &self.object_digest
    }
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

impl FormatTransformSelectionV1 {
    #[must_use]
    pub const fn built_in(transform: BuiltInFormatTransformV1) -> Self {
        Self::BuiltIn(transform)
    }

    #[must_use]
    pub const fn component(name: RichNameV1, component_digest: Digest) -> Self {
        Self::Component {
            name,
            component_digest,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::BuiltIn(transform) => transform.as_str(),
            Self::Component { name, .. } => name.as_str(),
        }
    }
}

/// A declared immutable object whose exact bytes are supplied to a transform.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransformResourceReferenceV1 {
    name: RichNameV1,
    source: CapturedPackFileReferenceV1,
}

impl TransformResourceReferenceV1 {
    #[must_use]
    pub const fn new(name: RichNameV1, source: CapturedPackFileReferenceV1) -> Self {
        Self { name, source }
    }
}

impl TransformResourceReferenceV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn source(&self) -> &CapturedPackFileReferenceV1 {
        &self.source
    }
}

/// A pure object or transform request selected for a desired output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesiredOutputKindV1 {
    RegularFile {
        source: CapturedPackFileReferenceV1,
        executable: bool,
    },
    Symlink {
        target: SafeRelativeSymlinkV1,
    },
    CanonicalTree {
        tree: Digest,
    },
    DecodedArchive {
        payload: CapturedPackFileReferenceV1,
        decoder: RichNameV1,
        decoder_version: u16,
        expected_tree: Digest,
    },
    TransformedFile {
        transform: FormatTransformSelectionV1,
        options: Vec<TransformOptionV1>,
        resources: Vec<TransformResourceReferenceV1>,
        executable: bool,
    },
}

/// A selected desired-output declaration with exact source provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredOutputV1 {
    name: RichNameV1,
    destination: TargetPathV1,
    slot: Option<RichNameV1>,
    kind: DesiredOutputKindV1,
    source: SourceLocationV1,
    profile: RichNameV1,
}

impl DesiredOutputV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn destination(&self) -> &TargetPathV1 {
        &self.destination
    }
    #[must_use]
    pub const fn slot(&self) -> Option<&RichNameV1> {
        self.slot.as_ref()
    }
    #[must_use]
    pub const fn kind(&self) -> &DesiredOutputKindV1 {
        &self.kind
    }
    #[must_use]
    pub const fn source(&self) -> &SourceLocationV1 {
        &self.source
    }
    #[must_use]
    pub const fn profile(&self) -> &RichNameV1 {
        &self.profile
    }
}

/// A desired output set sorted by name with disjoint destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredOutputSetV1 {
    outputs: BTreeMap<RichNameV1, DesiredOutputV1>,
}

impl DesiredOutputSetV1 {
    pub fn new(outputs: Vec<DesiredOutputV1>) -> Result<Self, RichConfigErrorV1> {
        if outputs.len() > MAX_RICH_OUTPUTS {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "desired outputs",
                limit: MAX_RICH_OUTPUTS,
                actual: outputs.len(),
            });
        }
        let mut by_name = BTreeMap::new();
        let mut destinations = BTreeSet::new();
        for output in outputs {
            if by_name.contains_key(&output.name) {
                return Err(RichConfigErrorV1::DuplicateName {
                    resource: "desired output",
                    name: output.name.as_str().to_owned(),
                });
            }
            insert_unique_key(&mut destinations, output.destination.clone(), |_| {
                RichConfigErrorV1::InvalidValue {
                    reason: "desired output destinations must be unique",
                }
            })?;
            by_name.insert(output.name.clone(), output);
        }
        let destinations = destinations.into_iter().collect::<Vec<_>>();
        for descendant in &destinations {
            for (separator, _) in descendant.as_str().match_indices('/') {
                let ancestor = &descendant.as_str()[..separator];
                if destinations
                    .binary_search_by(|candidate| candidate.as_str().cmp(ancestor))
                    .is_ok()
                {
                    return Err(RichConfigErrorV1::InvalidValue {
                        reason: "desired output destinations must not overlap",
                    });
                }
            }
        }
        Ok(Self { outputs: by_name })
    }
}

impl DesiredOutputSetV1 {
    #[must_use]
    pub const fn outputs(&self) -> &BTreeMap<RichNameV1, DesiredOutputV1> {
        &self.outputs
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RichTransformResourceReferenceV1 {
    pub(crate) name: RichNameV1,
    pub(crate) source: RichPackFileReferenceV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RichOutputDeclarationKindV1 {
    RegularFile {
        source: RichPackFileReferenceV1,
        executable: bool,
    },
    Symlink {
        target: SafeRelativeSymlinkV1,
    },
    CanonicalTree {
        tree: Digest,
    },
    DecodedArchive {
        payload: RichPackFileReferenceV1,
        decoder: RichNameV1,
        decoder_version: u16,
        expected_tree: Digest,
    },
    TransformedFile {
        transform: FormatTransformSelectionV1,
        options: Vec<TransformOptionV1>,
        resources: Vec<RichTransformResourceReferenceV1>,
        executable: bool,
    },
}

/// An output declaration retained on a profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichOutputDeclarationV1 {
    name: RichNameV1,
    destination: TargetPathV1,
    slot: Option<RichNameV1>,
    kind: RichOutputDeclarationKindV1,
    source: SourceLocationV1,
}

/// Fields shared by every output declaration.
///
/// Grouping them keeps each constructor from repeating four positional arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichOutputSiteV1 {
    name: RichNameV1,
    destination: TargetPathV1,
    slot: Option<RichNameV1>,
    source: SourceLocationV1,
}

impl RichOutputSiteV1 {
    #[must_use]
    pub const fn new(
        name: RichNameV1,
        destination: TargetPathV1,
        slot: Option<RichNameV1>,
        source: SourceLocationV1,
    ) -> Self {
        Self {
            name,
            destination,
            slot,
            source,
        }
    }
}

impl RichOutputSiteV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn destination(&self) -> &TargetPathV1 {
        &self.destination
    }
    #[must_use]
    pub const fn slot(&self) -> Option<&RichNameV1> {
        self.slot.as_ref()
    }
    #[must_use]
    pub const fn source(&self) -> &SourceLocationV1 {
        &self.source
    }
}

impl RichOutputDeclarationV1 {
    fn at(site: RichOutputSiteV1, kind: RichOutputDeclarationKindV1) -> Self {
        let RichOutputSiteV1 {
            name,
            destination,
            slot,
            source,
        } = site;
        Self {
            name,
            destination,
            slot,
            kind,
            source,
        }
    }

    #[must_use]
    pub(crate) fn regular_file(
        site: RichOutputSiteV1,
        source_reference: RichPackFileReferenceV1,
        executable: bool,
    ) -> Self {
        Self::at(
            site,
            RichOutputDeclarationKindV1::RegularFile {
                source: source_reference,
                executable,
            },
        )
    }

    #[must_use]
    pub fn symlink(site: RichOutputSiteV1, target: SafeRelativeSymlinkV1) -> Self {
        Self::at(site, RichOutputDeclarationKindV1::Symlink { target })
    }

    #[must_use]
    pub fn canonical_tree(site: RichOutputSiteV1, tree: Digest) -> Self {
        Self::at(site, RichOutputDeclarationKindV1::CanonicalTree { tree })
    }

    #[must_use]
    pub(crate) fn decoded_archive(
        site: RichOutputSiteV1,
        payload: RichPackFileReferenceV1,
        decoder: RichNameV1,
        decoder_version: u16,
        expected_tree: Digest,
    ) -> Self {
        Self::at(
            site,
            RichOutputDeclarationKindV1::DecodedArchive {
                payload,
                decoder,
                decoder_version,
                expected_tree,
            },
        )
    }

    pub(crate) fn transformed_file(
        site: RichOutputSiteV1,
        transform: FormatTransformSelectionV1,
        mut options: Vec<TransformOptionV1>,
        mut resources: Vec<RichTransformResourceReferenceV1>,
        executable: bool,
    ) -> Result<Self, RichConfigErrorV1> {
        if options.len() > MAX_TRANSFORM_OPTIONS {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform options",
                limit: MAX_TRANSFORM_OPTIONS,
                actual: options.len(),
            });
        }
        if resources.len() > MAX_TRANSFORM_RESOURCES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "transform resources",
                limit: MAX_TRANSFORM_RESOURCES,
                actual: resources.len(),
            });
        }
        options.sort_by(|left, right| left.name().cmp(right.name()));
        for pair in options.windows(2) {
            if pair[0].name() == pair[1].name() {
                return Err(RichConfigErrorV1::DuplicateName {
                    resource: "transform option",
                    name: pair[1].name().as_str().to_owned(),
                });
            }
        }
        resources.sort();
        for pair in resources.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(RichConfigErrorV1::DuplicateName {
                    resource: "transform resource",
                    name: pair[1].name.as_str().to_owned(),
                });
            }
        }
        Ok(Self::at(
            site,
            RichOutputDeclarationKindV1::TransformedFile {
                transform,
                options,
                resources,
                executable,
            },
        ))
    }

    fn select(
        &self,
        profile: RichNameV1,
        authorities: &CapturedAuthorityGraphV1,
    ) -> Result<DesiredOutputV1, RichConfigErrorV1> {
        let kind = match &self.kind {
            RichOutputDeclarationKindV1::RegularFile { source, executable } => {
                DesiredOutputKindV1::RegularFile {
                    source: resolve_pack_file_reference(authorities, &self.source, source)?,
                    executable: *executable,
                }
            }
            RichOutputDeclarationKindV1::Symlink { target } => DesiredOutputKindV1::Symlink {
                target: target.clone(),
            },
            RichOutputDeclarationKindV1::CanonicalTree { tree } => {
                DesiredOutputKindV1::CanonicalTree { tree: tree.clone() }
            }
            RichOutputDeclarationKindV1::DecodedArchive {
                payload,
                decoder,
                decoder_version,
                expected_tree,
            } => DesiredOutputKindV1::DecodedArchive {
                payload: resolve_pack_file_reference(authorities, &self.source, payload)?,
                decoder: decoder.clone(),
                decoder_version: *decoder_version,
                expected_tree: expected_tree.clone(),
            },
            RichOutputDeclarationKindV1::TransformedFile {
                transform,
                options,
                resources,
                executable,
            } => {
                let resources = resources
                    .iter()
                    .map(|resource| {
                        resolve_pack_file_reference(authorities, &self.source, &resource.source)
                            .map(|source| {
                                TransformResourceReferenceV1::new(resource.name.clone(), source)
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                DesiredOutputKindV1::TransformedFile {
                    transform: transform.clone(),
                    options: options.clone(),
                    resources,
                    executable: *executable,
                }
            }
        };
        Ok(DesiredOutputV1 {
            name: self.name.clone(),
            destination: self.destination.clone(),
            slot: self.slot.clone(),
            kind,
            source: self.source.clone(),
            profile,
        })
    }
}

impl RichOutputDeclarationV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn destination(&self) -> &TargetPathV1 {
        &self.destination
    }
    #[must_use]
    pub const fn slot(&self) -> Option<&RichNameV1> {
        self.slot.as_ref()
    }
    #[must_use]
    pub const fn source(&self) -> &SourceLocationV1 {
        &self.source
    }
}

fn resolve_pack_file_reference(
    authorities: &CapturedAuthorityGraphV1,
    source: &SourceLocationV1,
    reference: &RichPackFileReferenceV1,
) -> Result<CapturedPackFileReferenceV1, RichConfigErrorV1> {
    let authority =
        authorities.resolve_scope(source.document().authority(), reference.dependency.as_ref())?;
    Ok(CapturedPackFileReferenceV1 {
        authority,
        path: reference.path.clone(),
        kind: reference.kind,
        raw_digest: reference.raw_digest.clone(),
        object_digest: reference.object_digest.clone(),
        byte_len: reference.byte_len,
    })
}

/// A bounded named provider slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichSlotV1 {
    name: RichNameV1,
    max: usize,
    source: SourceLocationV1,
}

impl RichSlotV1 {
    pub fn new(
        name: RichNameV1,
        max: usize,
        source: SourceLocationV1,
    ) -> Result<Self, RichConfigErrorV1> {
        if max == 0 || max > MAX_RICH_SLOT_PROVIDERS {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "slot maximum must be between 1 and the provider limit",
            });
        }
        Ok(Self { name, max, source })
    }
}

impl RichSlotV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn max(&self) -> usize {
        self.max
    }
    #[must_use]
    pub const fn source(&self) -> &SourceLocationV1 {
        &self.source
    }
}

/// A profile layer containing IR statements and pure output declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichProfileV1 {
    name: RichNameV1,
    abstract_profile: bool,
    extends: Vec<RichNameV1>,
    statements: Vec<RichStatementV1>,
    outputs: Vec<RichOutputDeclarationV1>,
    source: SourceLocationV1,
}

impl RichProfileV1 {
    pub fn new(
        name: RichNameV1,
        abstract_profile: bool,
        extends: Vec<RichNameV1>,
        statements: Vec<RichStatementV1>,
        outputs: Vec<RichOutputDeclarationV1>,
        source: SourceLocationV1,
    ) -> Result<Self, RichConfigErrorV1> {
        if extends.len() > MAX_RICH_PROFILE_PARENTS {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "rich profile parents",
                limit: MAX_RICH_PROFILE_PARENTS,
                actual: extends.len(),
            });
        }
        if outputs.len() > MAX_RICH_OUTPUTS {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "rich profile outputs",
                limit: MAX_RICH_OUTPUTS,
                actual: outputs.len(),
            });
        }
        let mut parents = BTreeSet::new();
        for parent in &extends {
            insert_unique_key(&mut parents, parent, |parent| {
                RichConfigErrorV1::DuplicateName {
                    resource: "rich profile parent",
                    name: parent.as_str().to_owned(),
                }
            })?;
        }
        let mut output_names = BTreeSet::new();
        for output in &outputs {
            insert_unique_key(&mut output_names, output.name(), |name| {
                RichConfigErrorV1::DuplicateName {
                    resource: "profile output",
                    name: name.as_str().to_owned(),
                }
            })?;
        }
        Ok(Self {
            name,
            abstract_profile,
            extends,
            statements,
            outputs,
            source,
        })
    }
}

impl RichProfileV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.abstract_profile
    }
    #[must_use]
    pub fn extends(&self) -> &[RichNameV1] {
        &self.extends
    }
    #[must_use]
    pub fn statements(&self) -> &[RichStatementV1] {
        &self.statements
    }
    #[must_use]
    pub fn outputs(&self) -> &[RichOutputDeclarationV1] {
        &self.outputs
    }
    #[must_use]
    pub const fn source(&self) -> &SourceLocationV1 {
        &self.source
    }
}

/// A parsed rich KDL source and its exact captured semantic body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRichConfigDocumentV1 {
    id: CapturedDocumentIdV1,
    bytes: Vec<u8>,
    digest: Digest,
    includes: Vec<RichIncludeReferenceV1>,
    modules: Vec<RichModuleReferenceV1>,
    body: crate::RichDocumentBodyV1,
    default_profile: Option<(RichNameV1, SourceRangeV1)>,
    slots: BTreeMap<RichNameV1, RichSlotV1>,
    profiles: BTreeMap<RichNameV1, RichProfileV1>,
}

/// Inputs validated by [`ParsedRichConfigDocumentV1::new`].
///
/// The constructor enforces all limits and uniqueness rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRichConfigDocumentPartsV1 {
    pub id: CapturedDocumentIdV1,
    pub bytes: Vec<u8>,
    pub includes: Vec<RichIncludeReferenceV1>,
    pub modules: Vec<RichModuleReferenceV1>,
    pub body: crate::RichDocumentBodyV1,
    pub default_profile: Option<(RichNameV1, SourceRangeV1)>,
    pub slots: Vec<RichSlotV1>,
    pub profiles: Vec<RichProfileV1>,
}

impl ParsedRichConfigDocumentV1 {
    pub fn new(parts: ParsedRichConfigDocumentPartsV1) -> Result<Self, RichConfigErrorV1> {
        let ParsedRichConfigDocumentPartsV1 {
            id,
            bytes,
            includes,
            modules,
            body,
            default_profile,
            slots,
            profiles,
        } = parts;
        if slots.len() > MAX_RICH_SLOTS {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "rich slots",
                limit: MAX_RICH_SLOTS,
                actual: slots.len(),
            });
        }
        if profiles.len() > MAX_RICH_PROFILES {
            return Err(RichConfigErrorV1::LimitExceeded {
                resource: "rich profiles",
                limit: MAX_RICH_PROFILES,
                actual: profiles.len(),
            });
        }
        let mut slots_by_name = BTreeMap::new();
        for slot in slots {
            if slot.source.document() != &id {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "slot source must belong to its captured document",
                });
            }
            let name = slot.name.clone();
            insert_unique(&mut slots_by_name, name, slot, |name| {
                RichConfigErrorV1::DuplicateName {
                    resource: "rich slot",
                    name: name.into_inner(),
                }
            })?;
        }
        let mut profiles_by_name = BTreeMap::new();
        for profile in profiles {
            if profile.source.document() != &id
                || profile
                    .outputs
                    .iter()
                    .any(|output| output.source.document() != &id)
            {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "profile sources must belong to their captured document",
                });
            }
            let name = profile.name.clone();
            insert_unique(&mut profiles_by_name, name, profile, |name| {
                RichConfigErrorV1::DuplicateName {
                    resource: "rich profile",
                    name: name.into_inner(),
                }
            })?;
        }
        Ok(Self {
            digest: Digest::sha256(&bytes),
            id,
            bytes,
            includes,
            modules,
            body,
            default_profile,
            slots: slots_by_name,
            profiles: profiles_by_name,
        })
    }

    #[must_use]
    pub fn default_profile(&self) -> Option<&RichNameV1> {
        self.default_profile.as_ref().map(|(name, _)| name)
    }
}

impl ParsedRichConfigDocumentV1 {
    #[must_use]
    pub const fn id(&self) -> &CapturedDocumentIdV1 {
        &self.id
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
    #[must_use]
    pub fn includes(&self) -> &[RichIncludeReferenceV1] {
        &self.includes
    }
    #[must_use]
    pub fn modules(&self) -> &[RichModuleReferenceV1] {
        &self.modules
    }
    #[must_use]
    pub const fn slots(&self) -> &BTreeMap<RichNameV1, RichSlotV1> {
        &self.slots
    }
    #[must_use]
    pub const fn profiles(&self) -> &BTreeMap<RichNameV1, RichProfileV1> {
        &self.profiles
    }
}

/// A finite set of parsed rich sources and their captured include universe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRichConfigSetV1 {
    sources: BTreeMap<CapturedDocumentIdV1, ParsedRichConfigDocumentV1>,
    captured: CapturedDocumentSetV1,
}

impl ParsedRichConfigSetV1 {
    pub fn new(
        authorities: CapturedAuthorityGraphV1,
        sources: Vec<ParsedRichConfigDocumentV1>,
    ) -> Result<Self, RichConfigErrorV1> {
        let captured_documents = sources
            .iter()
            .map(|source| {
                let mut edges =
                    Vec::with_capacity(source.includes.len().saturating_add(source.modules.len()));
                for include in &source.includes {
                    let target = authorities.resolve_include(source.id.authority(), include)?;
                    edges.push(match include.dependency().cloned() {
                        Some(dependency) => {
                            CapturedIncludeV1::direct_include(target, dependency, include.range())
                        }
                        None => CapturedIncludeV1::new(target, include.range()),
                    });
                }
                for module in &source.modules {
                    let target = authorities.resolve_module(source.id.authority(), module)?;
                    edges.push(CapturedIncludeV1::module(
                        target,
                        module.module().clone(),
                        module.dependency().cloned(),
                        module.range(),
                    ));
                }
                CapturedConfigDocumentV1::new(
                    source.id.clone(),
                    source.bytes.clone(),
                    edges,
                    source.body.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let captured = CapturedDocumentSetV1::new(authorities, captured_documents)?;
        let mut by_id = BTreeMap::new();
        for source in sources {
            let id = source.id.clone();
            insert_unique(&mut by_id, id, source, |id| {
                RichConfigErrorV1::DuplicateName {
                    resource: "parsed rich document",
                    name: id.to_string(),
                }
            })?;
        }
        Ok(Self {
            sources: by_id,
            captured,
        })
    }

    pub fn evaluate(
        &self,
        entry: &CapturedDocumentIdV1,
        selected: Option<&RichNameV1>,
        supplied: &BTreeMap<RichNameV1, TypedValueV1>,
    ) -> Result<EvaluatedRichConfigV1, RichEvaluationErrorV1> {
        let order = reachable_rich_document_order_v1(&self.captured, entry)?;
        let entry_source = self.sources.get(entry).ok_or_else(|| {
            workspace_error(
                "missing-rich-entry",
                format!("entry document {entry} has no parsed rich source"),
                None,
            )
        })?;
        let selected = selected.cloned().or_else(|| {
            entry_source
                .default_profile
                .as_ref()
                .map(|(name, _)| name.clone())
        });
        let selected = selected.ok_or_else(|| {
            workspace_error(
                "missing-default-profile",
                "entry rich-config has no default profile and none was selected",
                Some(SourceLocationV1::new(
                    entry.clone(),
                    SourceRangeV1::synthetic(),
                )),
            )
        })?;

        let mut slots = BTreeMap::new();
        let mut profiles = BTreeMap::new();
        for id in &order {
            let source = self.sources.get(id).ok_or_else(|| {
                workspace_error(
                    "missing-parsed-include",
                    format!("captured document {id} has no parsed rich source"),
                    None,
                )
            })?;
            validate_declaration_ranges(source)?;
            for (name, slot) in &source.slots {
                check_admission(
                    &slots,
                    name,
                    AdmissionLimitV1 {
                        limit: MAX_RICH_SLOTS,
                        code: "slot-limit",
                        noun: "slot",
                    },
                    &slot.source,
                )?;
                insert_unique(&mut slots, name.clone(), slot.clone(), |name| {
                    workspace_error(
                        "duplicate-slot",
                        format!("slot {name} is declared more than once"),
                        Some(slot.source.clone()),
                    )
                })?;
            }
            for (name, profile) in &source.profiles {
                check_admission(
                    &profiles,
                    name,
                    AdmissionLimitV1 {
                        limit: MAX_RICH_PROFILES,
                        code: "profile-limit",
                        noun: "profile",
                    },
                    &profile.source,
                )?;
                insert_unique(&mut profiles, name.clone(), profile.clone(), |name| {
                    workspace_error(
                        "duplicate-profile",
                        format!("profile {name} is declared more than once"),
                        Some(profile.source.clone()),
                    )
                })?;
            }
        }
        if slots.len() > MAX_RICH_SLOTS {
            return Err(workspace_error(
                "slot-limit",
                format!("slot count exceeds {MAX_RICH_SLOTS}"),
                None,
            ));
        }
        if profiles.len() > MAX_RICH_PROFILES {
            return Err(workspace_error(
                "profile-limit",
                format!("profile count exceeds {MAX_RICH_PROFILES}"),
                None,
            ));
        }
        validate_profile_graph(&profiles)?;
        let profile = profiles.get(&selected).ok_or_else(|| {
            workspace_error(
                "unknown-profile",
                format!("selected profile {selected} is not declared"),
                None,
            )
        })?;
        if profile.abstract_profile {
            return Err(workspace_error(
                "abstract-profile",
                format!("profile {selected} is abstract and cannot be selected"),
                Some(profile.source.clone()),
            ));
        }
        let effective = effective_profiles(&profiles, &selected);
        let mut statements = Vec::new();
        let mut selected_outputs = BTreeMap::new();
        let mut active_slots: BTreeMap<RichNameV1, Vec<RichNameV1>> = BTreeMap::new();
        for profile_name in effective {
            let profile = profiles
                .get(&profile_name)
                .expect("effective profile names came from the validated map");
            if statements.len().saturating_add(profile.statements.len()) > MAX_RICH_STATEMENTS {
                return Err(workspace_error(
                    "statement-limit",
                    format!("effective profile statements exceed {MAX_RICH_STATEMENTS}"),
                    Some(profile.source.clone()),
                ));
            }
            statements.extend(profile.statements.iter().cloned().map(|statement| {
                LocatedRichStatementV1 {
                    document: profile.source.document().clone(),
                    statement,
                }
            }));
            for output in &profile.outputs {
                check_admission(
                    &selected_outputs,
                    output.name(),
                    AdmissionLimitV1 {
                        limit: MAX_RICH_OUTPUTS,
                        code: "output-limit",
                        noun: "desired output",
                    },
                    &output.source,
                )?;
                if selected_outputs.contains_key(output.name()) {
                    return Err(workspace_error(
                        "duplicate-inherited-output",
                        format!(
                            "profile composition repeats desired output {}",
                            output.name()
                        ),
                        Some(output.source.clone()),
                    ));
                }
                if let Some(slot_name) = output.slot() {
                    let slot = slots.get(slot_name).ok_or_else(|| {
                        workspace_error(
                            "unknown-output-slot",
                            format!(
                                "output {} references unknown slot {slot_name}",
                                output.name()
                            ),
                            Some(output.source.clone()),
                        )
                    })?;
                    let providers = active_slots.entry(slot_name.clone()).or_default();
                    if providers.len() >= slot.max {
                        return Err(workspace_error(
                            "slot-provider-limit",
                            format!("slot {slot_name} permits at most {} providers", slot.max),
                            Some(output.source.clone()),
                        ));
                    }
                    providers.push(output.name.clone());
                }
                let selected_output = output
                    .select(profile_name.clone(), self.captured.authorities())
                    .map_err(|error| {
                        workspace_error(
                            "invalid-pack-file-reference",
                            error.to_string(),
                            Some(output.source.clone()),
                        )
                    })?;
                selected_outputs.insert(output.name.clone(), selected_output);
            }
        }
        validate_output_destinations(&selected_outputs)?;
        let desired_outputs = DesiredOutputSetV1::new(selected_outputs.into_values().collect())
            .map_err(|error| workspace_error("invalid-desired-outputs", error.to_string(), None))?;
        let evaluation =
            evaluate_rich_config_with_statements_v1(&self.captured, entry, supplied, statements)?;
        Ok(EvaluatedRichConfigV1 {
            selected_profile: selected,
            evaluation,
            active_slots,
            desired_outputs,
        })
    }
}

impl ParsedRichConfigSetV1 {
    #[must_use]
    pub const fn sources(&self) -> &BTreeMap<CapturedDocumentIdV1, ParsedRichConfigDocumentV1> {
        &self.sources
    }
    #[must_use]
    pub const fn captured(&self) -> &CapturedDocumentSetV1 {
        &self.captured
    }
}

fn validate_output_destinations(
    outputs: &BTreeMap<RichNameV1, DesiredOutputV1>,
) -> Result<(), RichEvaluationErrorV1> {
    let mut by_destination: BTreeMap<&str, &DesiredOutputV1> = BTreeMap::new();
    for output in outputs.values() {
        if by_destination
            .insert(output.destination.as_str(), output)
            .is_some()
        {
            return Err(workspace_error(
                "duplicate-output-destination",
                format!("multiple desired outputs target {}", output.destination),
                Some(output.source.clone()),
            ));
        }
    }
    for (destination, output) in &by_destination {
        for (separator, _) in destination.match_indices('/') {
            if by_destination.contains_key(&destination[..separator]) {
                return Err(workspace_error(
                    "overlapping-output-destination",
                    format!("desired output destination {destination} overlaps an ancestor"),
                    Some(output.source.clone()),
                ));
            }
        }
    }
    Ok(())
}

/// The complete, pure result of rich profile and canonical IR evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatedRichConfigV1 {
    selected_profile: RichNameV1,
    evaluation: RichEvaluationV1,
    active_slots: BTreeMap<RichNameV1, Vec<RichNameV1>>,
    desired_outputs: DesiredOutputSetV1,
}

impl EvaluatedRichConfigV1 {
    #[must_use]
    pub const fn selected_profile(&self) -> &RichNameV1 {
        &self.selected_profile
    }
    #[must_use]
    pub const fn evaluation(&self) -> &RichEvaluationV1 {
        &self.evaluation
    }
    #[must_use]
    pub const fn active_slots(&self) -> &BTreeMap<RichNameV1, Vec<RichNameV1>> {
        &self.active_slots
    }
    #[must_use]
    pub const fn desired_outputs(&self) -> &DesiredOutputSetV1 {
        &self.desired_outputs
    }
}

fn validate_declaration_ranges(
    source: &ParsedRichConfigDocumentV1,
) -> Result<(), RichEvaluationErrorV1> {
    let byte_len = source.bytes.len();
    if let Some((_, range)) = &source.default_profile {
        validate_source_range(&source.id, *range, byte_len)?;
    }
    for slot in source.slots.values() {
        validate_source_range(slot.source.document(), slot.source.range(), byte_len)?;
    }
    for profile in source.profiles.values() {
        validate_source_range(profile.source.document(), profile.source.range(), byte_len)?;
        for output in &profile.outputs {
            validate_source_range(output.source.document(), output.source.range(), byte_len)?;
        }
    }
    Ok(())
}

fn validate_source_range(
    document: &CapturedDocumentIdV1,
    range: SourceRangeV1,
    byte_len: usize,
) -> Result<(), RichEvaluationErrorV1> {
    if usize::try_from(range.end()).unwrap_or(usize::MAX) > byte_len {
        return Err(workspace_error(
            "invalid-source-range",
            format!(
                "source range {}..{} exceeds {byte_len} captured bytes",
                range.start(),
                range.end()
            ),
            Some(SourceLocationV1::new(document.clone(), range)),
        ));
    }
    Ok(())
}

fn validate_profile_graph(
    profiles: &BTreeMap<RichNameV1, RichProfileV1>,
) -> Result<(), RichEvaluationErrorV1> {
    for profile in profiles.values() {
        for parent in &profile.extends {
            if !profiles.contains_key(parent) {
                return Err(workspace_error(
                    "unknown-profile-parent",
                    format!("profile {} extends unknown profile {parent}", profile.name),
                    Some(profile.source.clone()),
                ));
            }
        }
    }
    let mut colors = BTreeMap::new();
    for name in profiles.keys() {
        visit_profile(name, profiles, &mut colors, 1)?;
    }
    Ok(())
}

fn visit_profile(
    name: &RichNameV1,
    profiles: &BTreeMap<RichNameV1, RichProfileV1>,
    colors: &mut BTreeMap<RichNameV1, u8>,
    depth: usize,
) -> Result<(), RichEvaluationErrorV1> {
    if depth > MAX_RICH_PROFILE_DEPTH {
        let profile = profiles
            .get(name)
            .expect("profile graph names were validated");
        return Err(workspace_error(
            "profile-depth-limit",
            format!("profile inheritance depth exceeds {MAX_RICH_PROFILE_DEPTH}"),
            Some(profile.source.clone()),
        ));
    }
    match colors.get(name) {
        Some(2) => return Ok(()),
        Some(1) => {
            let profile = profiles
                .get(name)
                .expect("profile graph names were validated");
            return Err(workspace_error(
                "profile-cycle",
                format!("profile inheritance contains a cycle at {name}"),
                Some(profile.source.clone()),
            ));
        }
        _ => {}
    }
    colors.insert(name.clone(), 1);
    let profile = profiles
        .get(name)
        .expect("profile graph names were validated");
    for parent in &profile.extends {
        visit_profile(parent, profiles, colors, depth + 1)?;
    }
    colors.insert(name.clone(), 2);
    Ok(())
}

fn effective_profiles(
    profiles: &BTreeMap<RichNameV1, RichProfileV1>,
    selected: &RichNameV1,
) -> Vec<RichNameV1> {
    fn visit(
        profiles: &BTreeMap<RichNameV1, RichProfileV1>,
        name: &RichNameV1,
        visited: &mut BTreeSet<RichNameV1>,
        result: &mut Vec<RichNameV1>,
    ) {
        if !visited.insert(name.clone()) {
            return;
        }
        let profile = profiles
            .get(name)
            .expect("selected profile graph was validated");
        for parent in &profile.extends {
            visit(profiles, parent, visited, result);
        }
        result.push(name.clone());
    }

    let mut result = Vec::new();
    visit(profiles, selected, &mut BTreeSet::new(), &mut result);
    result
}

/// Per-call limits and diagnostic fields for bounded map admission.
#[derive(Clone, Copy)]
struct AdmissionLimitV1 {
    limit: usize,
    code: &'static str,
    noun: &'static str,
}

/// Rejects a new distinct key when the bounded map is full.
fn check_admission<V>(
    map: &BTreeMap<RichNameV1, V>,
    name: &RichNameV1,
    bound: AdmissionLimitV1,
    source: &SourceLocationV1,
) -> Result<(), RichEvaluationErrorV1> {
    if map.len() >= bound.limit && !map.contains_key(name) {
        let AdmissionLimitV1 { limit, code, noun } = bound;
        return Err(workspace_error(
            code,
            format!("{noun} count exceeds {limit}"),
            Some(source.clone()),
        ));
    }
    Ok(())
}

fn workspace_error(
    code: &str,
    message: impl Into<String>,
    source: Option<SourceLocationV1>,
) -> RichEvaluationErrorV1 {
    let message = message.into();
    let message = if message.len() <= crate::MAX_RICH_DIAGNOSTIC_BYTES {
        message
    } else {
        "rich workspace diagnostic exceeded its bounded detail limit".to_owned()
    };
    RichEvaluationErrorV1::one(
        RichDiagnosticV1::new(
            RichDiagnosticSeverityV1::Error,
            RichNameV1::new(code).expect("workspace diagnostic codes are valid"),
            message,
            source.map(RichDiagnosticLocationV1::Source),
            Vec::new(),
        )
        .expect("workspace diagnostics are bounded"),
    )
}
