use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use malm_pack::PackPath;
use malm_types::{Alias, ContributionName, Digest};

use crate::{
    FiniteFloatV1, MAX_CONFIG_DOCUMENT_BYTES, MAX_RICH_AUTHORITIES, MAX_RICH_COLLECTION_ITEMS,
    MAX_RICH_DIAGNOSTIC_BYTES, MAX_RICH_DIAGNOSTIC_NOTES, MAX_RICH_DOCUMENTS, MAX_RICH_FRAGMENTS,
    MAX_RICH_INCLUDES_PER_DOCUMENT, MAX_RICH_KEY_BYTES, MAX_RICH_NAME_BYTES,
    MAX_RICH_PROVENANCE_RECORDS, MAX_RICH_STATEMENTS, MAX_RICH_TEXT_BYTES,
    MAX_RICH_TOTAL_CAPTURED_BYTES, MAX_RICH_TOTAL_DIAGNOSTIC_BYTES, MAX_RICH_TOTAL_INCLUDES,
    MAX_RICH_TOTAL_VALUES, MAX_RICH_VALUE_DEPTH, MAX_RICH_VARIABLES, RICH_CONFIG_IR_VERSION,
};

/// Deterministic construction or validation failure for the rich config model.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum RichConfigErrorV1 {
    #[error("{resource} count/size {actual} exceeds limit {limit}")]
    LimitExceeded {
        resource: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("invalid {kind} ({value_len} bytes): {reason}")]
    InvalidName {
        kind: &'static str,
        value_len: usize,
        reason: &'static str,
    },
    #[error("duplicate {resource} name {name:?}")]
    DuplicateName {
        resource: &'static str,
        name: String,
    },
    #[error("invalid rich value: {reason}")]
    InvalidValue { reason: &'static str },
    #[error("expected {expected}, found {actual}")]
    TypeMismatch {
        expected: String,
        actual: &'static str,
    },
    #[error("required record field {0:?} is missing")]
    MissingRecordField(RichKeyV1),
    #[error("record contains undeclared field {0:?}")]
    UnknownRecordField(RichKeyV1),
    #[error("invalid source byte range {start}..{end}")]
    InvalidSourceRange { start: u32, end: u32 },
}

fn check_limit(
    resource: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), RichConfigErrorV1> {
    if actual > limit {
        Err(RichConfigErrorV1::LimitExceeded {
            resource,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

/// Inserts `key` into `map` and uses the caller's error for duplicates.
///
/// The callback receives the rejected key so each caller controls its error
/// variant, resource name, and spelling.
pub(crate) fn insert_unique<K, V, E>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    duplicate: impl FnOnce(K) -> E,
) -> Result<(), E>
where
    K: Clone + Ord,
{
    if map.insert(key.clone(), value).is_some() {
        return Err(duplicate(key));
    }
    Ok(())
}

/// Inserts a unique set key and uses the caller's error for duplicates.
pub(crate) fn insert_unique_key<K, E>(
    set: &mut BTreeSet<K>,
    key: K,
    duplicate: impl FnOnce(K) -> E,
) -> Result<(), E>
where
    K: Clone + Ord,
{
    if set.insert(key.clone()) {
        Ok(())
    } else {
        Err(duplicate(key))
    }
}

malm_types::validated_string! {
    /// A dotted, lowercase name used for variables, fragments, and loop bindings.
    pub struct RichNameV1;
    error: RichConfigErrorV1;
    validate: validate_rich_name;
    make_error: |value, reason| RichConfigErrorV1::InvalidName {
        kind: "rich name",
        value_len: value.len(),
        reason,
    };
    impl: borrow_str;
}

fn validate_rich_name(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.len() > MAX_RICH_NAME_BYTES {
        return Err("is too long");
    }
    for segment in value.split('.') {
        let Some((&first, rest)) = segment.as_bytes().split_first() else {
            return Err("must not contain empty dot-separated segments");
        };
        if !first.is_ascii_lowercase() {
            return Err("each segment must start with a lowercase ASCII letter");
        }
        if !rest.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
        }) {
            return Err(
                "segments may contain only lowercase ASCII letters, digits, hyphens, and underscores",
            );
        }
    }
    Ok(())
}

malm_types::validated_string! {
    /// A bounded UTF-8 key in a record, collection, option map, or value path.
    pub struct RichKeyV1;
    error: RichConfigErrorV1;
    validate: validate_rich_key;
    make_error: |value, reason| RichConfigErrorV1::InvalidName {
        kind: "rich key",
        value_len: value.len(),
        reason,
    };
    impl: borrow_str;
}

fn validate_rich_key(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.len() > MAX_RICH_KEY_BYTES {
        return Err("is too long");
    }
    if value.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    Ok(())
}

/// The exact authority attached by the acquisition layer to captured config bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DocumentAuthorityV1 {
    label: ContributionName,
    identity: Digest,
}

impl DocumentAuthorityV1 {
    #[must_use]
    pub const fn new(label: ContributionName, identity: Digest) -> Self {
        Self { label, identity }
    }
}

impl DocumentAuthorityV1 {
    #[must_use]
    pub const fn label(&self) -> &ContributionName {
        &self.label
    }
    #[must_use]
    pub const fn identity(&self) -> &Digest {
        &self.identity
    }
}

/// The exact locked-pack authority available to the capability-free config core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedAuthorityV1 {
    authority: DocumentAuthorityV1,
    dependencies: BTreeMap<Alias, DocumentAuthorityV1>,
    modules: BTreeMap<ContributionName, PackPath>,
    documents: BTreeSet<PackPath>,
}

impl CapturedAuthorityV1 {
    pub fn new(
        authority: DocumentAuthorityV1,
        dependencies: Vec<(Alias, DocumentAuthorityV1)>,
        modules: Vec<(ContributionName, PackPath)>,
        documents: Vec<PackPath>,
    ) -> Result<Self, RichConfigErrorV1> {
        let mut dependencies_by_alias = BTreeMap::new();
        for (alias, target) in dependencies {
            insert_unique(&mut dependencies_by_alias, alias, target, |alias| {
                RichConfigErrorV1::DuplicateName {
                    resource: "authority dependency alias",
                    name: alias.into_inner(),
                }
            })?;
        }
        let mut modules_by_name = BTreeMap::new();
        let mut module_paths = BTreeSet::new();
        for (name, path) in modules {
            insert_unique(&mut modules_by_name, name, path.clone(), |name| {
                RichConfigErrorV1::DuplicateName {
                    resource: "authority module",
                    name: name.into_inner(),
                }
            })?;
            insert_unique_key(&mut module_paths, path, |path| {
                RichConfigErrorV1::DuplicateName {
                    resource: "authority module path",
                    name: path.into_inner(),
                }
            })?;
        }
        let mut declared_documents = BTreeSet::new();
        for path in documents {
            insert_unique_key(&mut declared_documents, path.clone(), |path| {
                RichConfigErrorV1::DuplicateName {
                    resource: "authority config document",
                    name: path.into_inner(),
                }
            })?;
            if module_paths.contains(&path) {
                return Err(RichConfigErrorV1::DuplicateName {
                    resource: "authority config/module path",
                    name: path.into_inner(),
                });
            }
        }
        Ok(Self {
            authority,
            dependencies: dependencies_by_alias,
            modules: modules_by_name,
            documents: declared_documents,
        })
    }
}

impl CapturedAuthorityV1 {
    #[must_use]
    pub const fn authority(&self) -> &DocumentAuthorityV1 {
        &self.authority
    }
    #[must_use]
    pub const fn dependencies(&self) -> &BTreeMap<Alias, DocumentAuthorityV1> {
        &self.dependencies
    }
    #[must_use]
    pub const fn modules(&self) -> &BTreeMap<ContributionName, PackPath> {
        &self.modules
    }
    #[must_use]
    pub const fn documents(&self) -> &BTreeSet<PackPath> {
        &self.documents
    }
}

/// The complete finite authority graph supplied by locked acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedAuthorityGraphV1 {
    root: DocumentAuthorityV1,
    authorities: BTreeMap<DocumentAuthorityV1, CapturedAuthorityV1>,
}

impl CapturedAuthorityGraphV1 {
    pub fn new(
        root: DocumentAuthorityV1,
        authorities: Vec<CapturedAuthorityV1>,
    ) -> Result<Self, RichConfigErrorV1> {
        check_limit(
            "captured authorities",
            authorities.len(),
            MAX_RICH_AUTHORITIES,
        )?;
        let mut by_identity = BTreeMap::new();
        let mut labels = BTreeSet::new();
        for authority in authorities {
            insert_unique_key(&mut labels, authority.authority.label.clone(), |label| {
                RichConfigErrorV1::DuplicateName {
                    resource: "authority label",
                    name: label.as_str().to_owned(),
                }
            })?;
            let identity = authority.authority.clone();
            insert_unique(&mut by_identity, identity, authority, |identity| {
                RichConfigErrorV1::DuplicateName {
                    resource: "authority identity",
                    name: format!("{}@{}", identity.label, identity.identity),
                }
            })?;
        }
        if !by_identity.contains_key(&root) {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "captured authority root is missing",
            });
        }
        for authority in by_identity.values() {
            if authority
                .dependencies
                .values()
                .any(|target| !by_identity.contains_key(target))
            {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "authority dependency targets a missing exact identity",
                });
            }
        }
        let graph = Self {
            root,
            authorities: by_identity,
        };
        graph.validate_reachability()?;
        Ok(graph)
    }

    pub fn resolve_include(
        &self,
        from: &DocumentAuthorityV1,
        reference: &RichIncludeReferenceV1,
    ) -> Result<CapturedDocumentIdV1, RichConfigErrorV1> {
        let target = self.resolve_scope(from, reference.dependency.as_ref())?;
        let authority = self
            .authorities
            .get(&target)
            .ok_or(RichConfigErrorV1::InvalidValue {
                reason: "include resolved to an unknown authority",
            })?;
        if !authority.documents.contains(&reference.path) {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "include path is not declared by the exact target pack",
            });
        }
        Ok(CapturedDocumentIdV1::new(target, reference.path.clone()))
    }

    pub fn resolve_module(
        &self,
        from: &DocumentAuthorityV1,
        reference: &RichModuleReferenceV1,
    ) -> Result<CapturedDocumentIdV1, RichConfigErrorV1> {
        let target = self.resolve_scope(from, reference.dependency.as_ref())?;
        let authority = self
            .authorities
            .get(&target)
            .ok_or(RichConfigErrorV1::InvalidValue {
                reason: "module resolved to an unknown authority",
            })?;
        let path =
            authority
                .modules
                .get(&reference.module)
                .ok_or(RichConfigErrorV1::InvalidValue {
                    reason: "module is not declared by the exact target pack",
                })?;
        Ok(CapturedDocumentIdV1::new(target, path.clone()))
    }

    pub(crate) fn resolve_scope(
        &self,
        from: &DocumentAuthorityV1,
        dependency: Option<&Alias>,
    ) -> Result<DocumentAuthorityV1, RichConfigErrorV1> {
        let authority = self
            .authorities
            .get(from)
            .ok_or(RichConfigErrorV1::InvalidValue {
                reason: "document claims an authority outside the supplied locked graph",
            })?;
        match dependency {
            None => Ok(from.clone()),
            Some(alias) => {
                authority
                    .dependencies
                    .get(alias)
                    .cloned()
                    .ok_or(RichConfigErrorV1::InvalidValue {
                        reason: "document references an undeclared direct dependency alias",
                    })
            }
        }
    }

    fn validate_edge(
        &self,
        source: &CapturedDocumentIdV1,
        edge: &CapturedIncludeV1,
    ) -> Result<(), RichConfigErrorV1> {
        let expected = match edge.kind() {
            CapturedDocumentEdgeKindV1::Include => self.resolve_include(
                source.authority(),
                &RichIncludeReferenceV1::new(
                    edge.target.path.clone(),
                    edge.dependency.clone(),
                    edge.range,
                ),
            )?,
            CapturedDocumentEdgeKindV1::Module { name } => self.resolve_module(
                source.authority(),
                &RichModuleReferenceV1::new(name.clone(), edge.dependency.clone(), edge.range),
            )?,
        };
        if expected != edge.target {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "captured document edge forges an authority, identity, or path",
            });
        }
        Ok(())
    }

    fn validate_reachability(&self) -> Result<(), RichConfigErrorV1> {
        let mut colors = BTreeMap::new();
        let mut reachable = BTreeSet::new();
        self.visit_authority(&self.root, &mut colors, &mut reachable)?;
        if reachable.len() != self.authorities.len() {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "captured authority graph contains an unreachable locked pack",
            });
        }
        Ok(())
    }

    fn visit_authority(
        &self,
        current: &DocumentAuthorityV1,
        colors: &mut BTreeMap<DocumentAuthorityV1, u8>,
        reachable: &mut BTreeSet<DocumentAuthorityV1>,
    ) -> Result<(), RichConfigErrorV1> {
        match colors.get(current) {
            Some(2) => return Ok(()),
            Some(1) => {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "captured authority graph contains a dependency cycle",
                });
            }
            _ => {}
        }
        colors.insert(current.clone(), 1);
        reachable.insert(current.clone());
        let authority = &self.authorities[current];
        for target in authority.dependencies.values() {
            self.visit_authority(target, colors, reachable)?;
        }
        colors.insert(current.clone(), 2);
        Ok(())
    }
}

impl CapturedAuthorityGraphV1 {
    #[must_use]
    pub const fn root(&self) -> &DocumentAuthorityV1 {
        &self.root
    }
    #[must_use]
    pub const fn authorities(&self) -> &BTreeMap<DocumentAuthorityV1, CapturedAuthorityV1> {
        &self.authorities
    }
}

/// Stable identity of an explicitly captured document.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapturedDocumentIdV1 {
    authority: DocumentAuthorityV1,
    path: PackPath,
}

/// Digest and exact byte length of a captured source document.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapturedSourceIdentityV1 {
    digest: Digest,
    byte_len: u64,
}

impl CapturedSourceIdentityV1 {
    pub fn new(digest: Digest, byte_len: u64) -> Result<Self, RichConfigErrorV1> {
        if byte_len > u64::try_from(MAX_CONFIG_DOCUMENT_BYTES).unwrap_or(u64::MAX) {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "captured source byte length exceeds the document limit",
            });
        }
        Ok(Self { digest, byte_len })
    }
}

impl CapturedSourceIdentityV1 {
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

impl CapturedDocumentIdV1 {
    #[must_use]
    pub const fn new(authority: DocumentAuthorityV1, path: PackPath) -> Self {
        Self { authority, path }
    }
}

impl CapturedDocumentIdV1 {
    #[must_use]
    pub const fn authority(&self) -> &DocumentAuthorityV1 {
        &self.authority
    }
    #[must_use]
    pub const fn path(&self) -> &PackPath {
        &self.path
    }
}

impl fmt::Display for CapturedDocumentIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}@{}:{}",
            self.authority.label, self.authority.identity, self.path
        )
    }
}

/// A half-open range in a document's exact captured bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceRangeV1 {
    start: u32,
    end: u32,
}

impl SourceRangeV1 {
    pub const fn new(start: u32, end: u32) -> Result<Self, RichConfigErrorV1> {
        if start > end {
            return Err(RichConfigErrorV1::InvalidSourceRange { start, end });
        }
        Ok(Self { start, end })
    }

    #[must_use]
    pub const fn synthetic() -> Self {
        Self { start: 0, end: 0 }
    }
}

impl SourceRangeV1 {
    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }
    #[must_use]
    pub const fn end(self) -> u32 {
        self.end
    }
}

/// A fully qualified source location retained in diagnostics and provenance.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceLocationV1 {
    document: CapturedDocumentIdV1,
    range: SourceRangeV1,
}

impl SourceLocationV1 {
    #[must_use]
    pub const fn new(document: CapturedDocumentIdV1, range: SourceRangeV1) -> Self {
        Self { document, range }
    }
}

impl SourceLocationV1 {
    #[must_use]
    pub const fn document(&self) -> &CapturedDocumentIdV1 {
        &self.document
    }
    #[must_use]
    pub const fn range(&self) -> SourceRangeV1 {
        self.range
    }
}

/// A half-open range in transform output bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransformOutputRangeV1 {
    start: u64,
    end: u64,
}

impl TransformOutputRangeV1 {
    pub const fn new(start: u64, end: u64) -> Result<Self, RichConfigErrorV1> {
        if start > end {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "transform output range start must not exceed its end",
            });
        }
        Ok(Self { start, end })
    }
}

impl TransformOutputRangeV1 {
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }
}

/// Deterministically ordered diagnostic severity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RichDiagnosticSeverityV1 {
    Error,
    Warning,
    Info,
}

/// The source or generated-output location of a diagnostic.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RichDiagnosticLocationV1 {
    Source(SourceLocationV1),
    Output(TransformOutputRangeV1),
}

/// A bounded structured diagnostic shared by evaluation and transform contracts.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RichDiagnosticV1 {
    severity: RichDiagnosticSeverityV1,
    code: RichNameV1,
    message: String,
    primary: Option<RichDiagnosticLocationV1>,
    notes: Vec<String>,
}

impl RichDiagnosticV1 {
    pub fn new(
        severity: RichDiagnosticSeverityV1,
        code: RichNameV1,
        message: impl Into<String>,
        primary: Option<RichDiagnosticLocationV1>,
        notes: Vec<String>,
    ) -> Result<Self, RichConfigErrorV1> {
        let message = message.into();
        check_limit(
            "diagnostic message bytes",
            message.len(),
            MAX_RICH_DIAGNOSTIC_BYTES,
        )?;
        check_limit("diagnostic notes", notes.len(), MAX_RICH_DIAGNOSTIC_NOTES)?;
        let mut total = message.len();
        for note in &notes {
            check_limit(
                "diagnostic note bytes",
                note.len(),
                MAX_RICH_DIAGNOSTIC_BYTES,
            )?;
            total = total.saturating_add(note.len());
        }
        check_limit(
            "diagnostic text bytes",
            total,
            MAX_RICH_TOTAL_DIAGNOSTIC_BYTES,
        )?;
        Ok(Self {
            severity,
            code,
            message,
            primary,
            notes,
        })
    }
}

impl RichDiagnosticV1 {
    #[must_use]
    pub const fn severity(&self) -> RichDiagnosticSeverityV1 {
        self.severity
    }
    #[must_use]
    pub const fn code(&self) -> &RichNameV1 {
        &self.code
    }
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
    #[must_use]
    pub const fn primary(&self) -> Option<&RichDiagnosticLocationV1> {
        self.primary.as_ref()
    }
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }
}

/// Sorts diagnostics into their canonical order and enforces aggregate bounds.
pub(crate) fn canonical_diagnostics(
    mut diagnostics: Vec<RichDiagnosticV1>,
) -> Result<Vec<RichDiagnosticV1>, RichConfigErrorV1> {
    check_limit(
        "diagnostics",
        diagnostics.len(),
        crate::MAX_RICH_DIAGNOSTICS,
    )?;
    let total = diagnostics.iter().fold(0_usize, |total, diagnostic| {
        total
            .saturating_add(diagnostic.message.len())
            .saturating_add(diagnostic.notes.iter().map(String::len).sum::<usize>())
    });
    check_limit(
        "diagnostic text bytes",
        total,
        MAX_RICH_TOTAL_DIAGNOSTIC_BYTES,
    )?;
    diagnostics.sort();
    if let Some(duplicate) = diagnostics
        .windows(2)
        .find(|pair| pair[0] == pair[1])
        .map(|pair| &pair[0])
    {
        return Err(RichConfigErrorV1::DuplicateName {
            resource: "diagnostic",
            name: duplicate.code.as_str().to_owned(),
        });
    }
    Ok(diagnostics)
}

/// The public kind label of a canonical typed value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TypedValueKindV1 {
    Null,
    Boolean,
    Integer,
    Unsigned,
    Float,
    String,
    Path,
    List,
    Record,
    Collection,
}

impl TypedValueKindV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean => "bool",
            Self::Integer => "integer",
            Self::Unsigned => "unsigned",
            Self::Float => "float",
            Self::String => "string",
            Self::Path => "path",
            Self::List => "list",
            Self::Record => "record",
            Self::Collection => "collection",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TypedValueDataV1 {
    Null,
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    Float(FiniteFloatV1),
    String(String),
    Path(crate::TargetPathV1),
    List(Vec<TypedValueV1>),
    Record(BTreeMap<RichKeyV1, TypedValueV1>),
    Collection(BTreeMap<RichKeyV1, TypedValueV1>),
}

/// A canonical typed value with recursive bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedValueV1(pub(crate) TypedValueDataV1);

impl TypedValueV1 {
    #[must_use]
    pub const fn null() -> Self {
        Self(TypedValueDataV1::Null)
    }

    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self(TypedValueDataV1::Boolean(value))
    }

    #[must_use]
    pub const fn integer(value: i64) -> Self {
        Self(TypedValueDataV1::Integer(value))
    }

    #[must_use]
    pub const fn unsigned(value: u64) -> Self {
        Self(TypedValueDataV1::Unsigned(value))
    }

    pub fn float(value: f64) -> Result<Self, RichConfigErrorV1> {
        FiniteFloatV1::new(value)
            .map(|value| Self(TypedValueDataV1::Float(value)))
            .map_err(|_| RichConfigErrorV1::InvalidValue {
                reason: "float must be finite",
            })
    }

    pub fn string(value: impl Into<String>) -> Result<Self, RichConfigErrorV1> {
        let value = value.into();
        check_limit("rich string bytes", value.len(), MAX_RICH_TEXT_BYTES)?;
        Ok(Self(TypedValueDataV1::String(value)))
    }

    #[must_use]
    pub const fn path(value: crate::TargetPathV1) -> Self {
        Self(TypedValueDataV1::Path(value))
    }

    pub fn list(values: Vec<Self>) -> Result<Self, RichConfigErrorV1> {
        check_limit("list items", values.len(), MAX_RICH_COLLECTION_ITEMS)?;
        let value = Self(TypedValueDataV1::List(values));
        value.validate()?;
        Ok(value)
    }

    pub fn record(values: BTreeMap<RichKeyV1, Self>) -> Result<Self, RichConfigErrorV1> {
        check_limit("record fields", values.len(), MAX_RICH_COLLECTION_ITEMS)?;
        let value = Self(TypedValueDataV1::Record(values));
        value.validate()?;
        Ok(value)
    }

    pub fn collection(values: BTreeMap<RichKeyV1, Self>) -> Result<Self, RichConfigErrorV1> {
        check_limit(
            "keyed collection items",
            values.len(),
            MAX_RICH_COLLECTION_ITEMS,
        )?;
        let value = Self(TypedValueDataV1::Collection(values));
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn kind(&self) -> TypedValueKindV1 {
        match self.0 {
            TypedValueDataV1::Null => TypedValueKindV1::Null,
            TypedValueDataV1::Boolean(_) => TypedValueKindV1::Boolean,
            TypedValueDataV1::Integer(_) => TypedValueKindV1::Integer,
            TypedValueDataV1::Unsigned(_) => TypedValueKindV1::Unsigned,
            TypedValueDataV1::Float(_) => TypedValueKindV1::Float,
            TypedValueDataV1::String(_) => TypedValueKindV1::String,
            TypedValueDataV1::Path(_) => TypedValueKindV1::Path,
            TypedValueDataV1::List(_) => TypedValueKindV1::List,
            TypedValueDataV1::Record(_) => TypedValueKindV1::Record,
            TypedValueDataV1::Collection(_) => TypedValueKindV1::Collection,
        }
    }

    pub fn validate(&self) -> Result<(), RichConfigErrorV1> {
        let mut total = 0_usize;
        validate_value_at(self, 1, &mut total)
    }
}

impl TypedValueV1 {
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match &self.0 {
            TypedValueDataV1::Boolean(value) => Some(*value),
            _ => None,
        }
    }
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match &self.0 {
            TypedValueDataV1::Integer(value) => Some(*value),
            _ => None,
        }
    }
    #[must_use]
    pub const fn as_unsigned(&self) -> Option<u64> {
        match &self.0 {
            TypedValueDataV1::Unsigned(value) => Some(*value),
            _ => None,
        }
    }
    #[must_use]
    pub const fn as_float(&self) -> Option<FiniteFloatV1> {
        match &self.0 {
            TypedValueDataV1::Float(value) => Some(*value),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match &self.0 {
            TypedValueDataV1::String(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub const fn as_path(&self) -> Option<&crate::TargetPathV1> {
        match &self.0 {
            TypedValueDataV1::Path(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_list(&self) -> Option<&[Self]> {
        match &self.0 {
            TypedValueDataV1::List(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub const fn as_record(&self) -> Option<&BTreeMap<RichKeyV1, Self>> {
        match &self.0 {
            TypedValueDataV1::Record(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub const fn as_collection(&self) -> Option<&BTreeMap<RichKeyV1, Self>> {
        match &self.0 {
            TypedValueDataV1::Collection(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub(crate) const fn as_record_mut(&mut self) -> Option<&mut BTreeMap<RichKeyV1, Self>> {
        match &mut self.0 {
            TypedValueDataV1::Record(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub(crate) fn as_list_mut(&mut self) -> Option<&mut Vec<Self>> {
        match &mut self.0 {
            TypedValueDataV1::List(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub(crate) const fn as_collection_mut(&mut self) -> Option<&mut BTreeMap<RichKeyV1, Self>> {
        match &mut self.0 {
            TypedValueDataV1::Collection(value) => Some(value),
            _ => None,
        }
    }
}

fn validate_value_at(
    value: &TypedValueV1,
    depth: usize,
    total: &mut usize,
) -> Result<(), RichConfigErrorV1> {
    check_limit("typed value depth", depth, MAX_RICH_VALUE_DEPTH)?;
    *total = total.saturating_add(1);
    check_limit("typed values", *total, MAX_RICH_TOTAL_VALUES)?;
    match &value.0 {
        TypedValueDataV1::String(value) => {
            check_limit("rich string bytes", value.len(), MAX_RICH_TEXT_BYTES)
        }
        TypedValueDataV1::List(values) => {
            check_limit("list items", values.len(), MAX_RICH_COLLECTION_ITEMS)?;
            for value in values {
                validate_value_at(value, depth + 1, total)?;
            }
            Ok(())
        }
        TypedValueDataV1::Record(values) => {
            check_limit("record fields", values.len(), MAX_RICH_COLLECTION_ITEMS)?;
            for value in values.values() {
                validate_value_at(value, depth + 1, total)?;
            }
            Ok(())
        }
        TypedValueDataV1::Collection(values) => {
            check_limit(
                "keyed collection items",
                values.len(),
                MAX_RICH_COLLECTION_ITEMS,
            )?;
            for value in values.values() {
                validate_value_at(value, depth + 1, total)?;
            }
            Ok(())
        }
        TypedValueDataV1::Null
        | TypedValueDataV1::Boolean(_)
        | TypedValueDataV1::Integer(_)
        | TypedValueDataV1::Unsigned(_)
        | TypedValueDataV1::Float(_)
        | TypedValueDataV1::Path(_) => Ok(()),
    }
}

/// Exact scalar type in a rich schema.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TypedScalarTypeV1 {
    Boolean,
    Integer,
    Unsigned,
    Float,
    String,
    Path,
}

/// The public structural kind of a recursive rich value type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TypedValueTypeKindV1 {
    Boolean,
    Integer,
    Unsigned,
    Float,
    String,
    Path,
    List,
    Record,
    Collection,
}

impl TypedValueTypeKindV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "bool",
            Self::Integer => "integer",
            Self::Unsigned => "unsigned",
            Self::Float => "float",
            Self::String => "string",
            Self::Path => "path",
            Self::List => "list",
            Self::Record => "record",
            Self::Collection => "collection",
        }
    }
}

impl TypedScalarTypeV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "bool",
            Self::Integer => "integer",
            Self::Unsigned => "unsigned",
            Self::Float => "float",
            Self::String => "string",
            Self::Path => "path",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TypedValueTypeDataV1 {
    Scalar(TypedScalarTypeV1),
    List(Box<TypedValueTypeV1>),
    Record(BTreeMap<RichKeyV1, TypedRecordFieldV1>),
    Collection(Box<TypedValueTypeV1>),
}

/// A closed recursive type for canonical rich values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedValueTypeV1(pub(crate) TypedValueTypeDataV1);

impl TypedValueTypeV1 {
    #[must_use]
    pub const fn boolean() -> Self {
        Self(TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Boolean))
    }

    #[must_use]
    pub const fn integer() -> Self {
        Self(TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Integer))
    }

    #[must_use]
    pub const fn unsigned() -> Self {
        Self(TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Unsigned))
    }

    #[must_use]
    pub const fn float() -> Self {
        Self(TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Float))
    }

    #[must_use]
    pub const fn string() -> Self {
        Self(TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::String))
    }

    #[must_use]
    pub const fn path() -> Self {
        Self(TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Path))
    }

    pub fn list(item: Self) -> Result<Self, RichConfigErrorV1> {
        let value = Self(TypedValueTypeDataV1::List(Box::new(item)));
        value.validate()?;
        Ok(value)
    }

    pub fn record(
        fields: BTreeMap<RichKeyV1, TypedRecordFieldV1>,
    ) -> Result<Self, RichConfigErrorV1> {
        check_limit(
            "record schema fields",
            fields.len(),
            MAX_RICH_COLLECTION_ITEMS,
        )?;
        let value = Self(TypedValueTypeDataV1::Record(fields));
        value.validate()?;
        Ok(value)
    }

    pub fn record_from_fields(
        fields: Vec<(RichKeyV1, TypedRecordFieldV1)>,
    ) -> Result<Self, RichConfigErrorV1> {
        let mut by_name = BTreeMap::new();
        for (name, field) in fields {
            insert_unique(&mut by_name, name, field, |name| {
                RichConfigErrorV1::DuplicateName {
                    resource: "record field",
                    name: name.into_inner(),
                }
            })?;
        }
        Self::record(by_name)
    }

    pub fn collection(item: Self) -> Result<Self, RichConfigErrorV1> {
        let value = Self(TypedValueTypeDataV1::Collection(Box::new(item)));
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn kind(&self) -> TypedValueTypeKindV1 {
        match &self.0 {
            TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Boolean) => {
                TypedValueTypeKindV1::Boolean
            }
            TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Integer) => {
                TypedValueTypeKindV1::Integer
            }
            TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Unsigned) => {
                TypedValueTypeKindV1::Unsigned
            }
            TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Float) => TypedValueTypeKindV1::Float,
            TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::String) => TypedValueTypeKindV1::String,
            TypedValueTypeDataV1::Scalar(TypedScalarTypeV1::Path) => TypedValueTypeKindV1::Path,
            TypedValueTypeDataV1::List(_) => TypedValueTypeKindV1::List,
            TypedValueTypeDataV1::Record(_) => TypedValueTypeKindV1::Record,
            TypedValueTypeDataV1::Collection(_) => TypedValueTypeKindV1::Collection,
        }
    }

    #[must_use]
    pub const fn scalar_kind(&self) -> Option<TypedScalarTypeV1> {
        match &self.0 {
            TypedValueTypeDataV1::Scalar(kind) => Some(*kind),
            TypedValueTypeDataV1::List(_)
            | TypedValueTypeDataV1::Record(_)
            | TypedValueTypeDataV1::Collection(_) => None,
        }
    }

    #[must_use]
    pub fn label(&self) -> String {
        match &self.0 {
            TypedValueTypeDataV1::Scalar(kind) => kind.as_str().to_owned(),
            TypedValueTypeDataV1::List(item) => format!("list<{}>", item.label()),
            TypedValueTypeDataV1::Record(_) => "record".to_owned(),
            TypedValueTypeDataV1::Collection(item) => {
                format!("collection<{}>", item.label())
            }
        }
    }

    /// Applies recursive record defaults and explicit nulls for optional fields.
    pub fn resolve(&self, value: &TypedValueV1) -> Result<TypedValueV1, RichConfigErrorV1> {
        resolve_typed_value(self, value, false)
    }

    pub(crate) fn resolve_optional(
        &self,
        value: &TypedValueV1,
        optional: bool,
    ) -> Result<TypedValueV1, RichConfigErrorV1> {
        resolve_typed_value(self, value, optional)
    }

    pub fn validate(&self) -> Result<(), RichConfigErrorV1> {
        let mut total = 0_usize;
        validate_type_at(self, 1, &mut total)
    }
}

impl TypedValueTypeV1 {
    #[must_use]
    pub const fn list_item_type(&self) -> Option<&Self> {
        match &self.0 {
            TypedValueTypeDataV1::List(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub const fn record_fields(&self) -> Option<&BTreeMap<RichKeyV1, TypedRecordFieldV1>> {
        match &self.0 {
            TypedValueTypeDataV1::Record(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub const fn collection_item_type(&self) -> Option<&Self> {
        match &self.0 {
            TypedValueTypeDataV1::Collection(value) => Some(value),
            _ => None,
        }
    }
}

fn validate_type_at(
    value_type: &TypedValueTypeV1,
    depth: usize,
    total: &mut usize,
) -> Result<(), RichConfigErrorV1> {
    check_limit("typed schema depth", depth, MAX_RICH_VALUE_DEPTH)?;
    *total = total.saturating_add(1);
    check_limit("typed schema nodes", *total, MAX_RICH_TOTAL_VALUES)?;
    match &value_type.0 {
        TypedValueTypeDataV1::List(item) | TypedValueTypeDataV1::Collection(item) => {
            validate_type_at(item, depth + 1, total)
        }
        TypedValueTypeDataV1::Record(fields) => {
            check_limit(
                "record schema fields",
                fields.len(),
                MAX_RICH_COLLECTION_ITEMS,
            )?;
            for field in fields.values() {
                validate_type_at(&field.value_type, depth + 1, total)?;
                if let Some(default) = &field.default {
                    field.value_type.resolve_optional(default, field.optional)?;
                }
            }
            Ok(())
        }
        TypedValueTypeDataV1::Scalar(_) => Ok(()),
    }
}

/// A field in a closed record schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedRecordFieldV1 {
    pub(crate) value_type: TypedValueTypeV1,
    pub(crate) optional: bool,
    pub(crate) default: Option<TypedValueV1>,
}

impl TypedRecordFieldV1 {
    #[must_use]
    pub const fn required(value_type: TypedValueTypeV1) -> Self {
        Self {
            value_type,
            optional: false,
            default: None,
        }
    }

    #[must_use]
    pub const fn optional(value_type: TypedValueTypeV1) -> Self {
        Self {
            value_type,
            optional: true,
            default: None,
        }
    }

    pub fn defaulted(
        value_type: TypedValueTypeV1,
        default: TypedValueV1,
    ) -> Result<Self, RichConfigErrorV1> {
        let default = value_type.resolve(&default)?;
        Ok(Self {
            value_type,
            optional: false,
            default: Some(default),
        })
    }

    pub fn optional_defaulted(
        value_type: TypedValueTypeV1,
        default: TypedValueV1,
    ) -> Result<Self, RichConfigErrorV1> {
        let default = value_type.resolve_optional(&default, true)?;
        Ok(Self {
            value_type,
            optional: true,
            default: Some(default),
        })
    }
}

impl TypedRecordFieldV1 {
    #[must_use]
    pub const fn value_type(&self) -> &TypedValueTypeV1 {
        &self.value_type
    }
    #[must_use]
    pub const fn is_optional(&self) -> bool {
        self.optional
    }
    #[must_use]
    pub const fn default(&self) -> Option<&TypedValueV1> {
        self.default.as_ref()
    }
}

fn resolve_typed_value(
    value_type: &TypedValueTypeV1,
    value: &TypedValueV1,
    optional: bool,
) -> Result<TypedValueV1, RichConfigErrorV1> {
    if value.kind() == TypedValueKindV1::Null {
        return if optional {
            Ok(TypedValueV1::null())
        } else {
            Err(RichConfigErrorV1::TypeMismatch {
                expected: value_type.label(),
                actual: TypedValueKindV1::Null.as_str(),
            })
        };
    }
    match (&value_type.0, &value.0) {
        (TypedValueTypeDataV1::Scalar(expected), actual) if scalar_accepts(*expected, actual) => {
            Ok(value.clone())
        }
        (TypedValueTypeDataV1::List(item_type), TypedValueDataV1::List(values)) => {
            let values = values
                .iter()
                .map(|value| resolve_typed_value(item_type, value, false))
                .collect::<Result<Vec<_>, _>>()?;
            TypedValueV1::list(values)
        }
        (TypedValueTypeDataV1::Collection(item_type), TypedValueDataV1::Collection(values)) => {
            let values = values
                .iter()
                .map(|(key, value)| {
                    resolve_typed_value(item_type, value, false).map(|value| (key.clone(), value))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            TypedValueV1::collection(values)
        }
        (TypedValueTypeDataV1::Record(fields), TypedValueDataV1::Record(values)) => {
            if let Some(unknown) = values.keys().find(|name| !fields.contains_key(*name)) {
                return Err(RichConfigErrorV1::UnknownRecordField(unknown.clone()));
            }
            let mut resolved = BTreeMap::new();
            for (name, field) in fields {
                let value = match values.get(name) {
                    Some(value) => field.value_type.resolve_optional(value, field.optional)?,
                    None if field.default.is_some() => {
                        field.default.as_ref().expect("checked above").clone()
                    }
                    None if field.optional => TypedValueV1::null(),
                    None => return Err(RichConfigErrorV1::MissingRecordField(name.clone())),
                };
                resolved.insert(name.clone(), value);
            }
            TypedValueV1::record(resolved)
        }
        _ => Err(RichConfigErrorV1::TypeMismatch {
            expected: value_type.label(),
            actual: value.kind().as_str(),
        }),
    }
}

const fn scalar_accepts(expected: TypedScalarTypeV1, actual: &TypedValueDataV1) -> bool {
    matches!(
        (expected, actual),
        (TypedScalarTypeV1::Boolean, TypedValueDataV1::Boolean(_))
            | (TypedScalarTypeV1::Integer, TypedValueDataV1::Integer(_))
            | (TypedScalarTypeV1::Unsigned, TypedValueDataV1::Unsigned(_))
            | (TypedScalarTypeV1::Float, TypedValueDataV1::Float(_))
            | (TypedScalarTypeV1::String, TypedValueDataV1::String(_))
            | (TypedScalarTypeV1::Path, TypedValueDataV1::Path(_))
    )
}

/// A pure expression evaluated against named variables and lexical loop bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RichExpressionV1 {
    Literal(TypedValueV1),
    Variable(RichNameV1),
    List(Vec<Self>),
    Record(BTreeMap<RichKeyV1, Self>),
    Collection(BTreeMap<RichKeyV1, Self>),
    Select {
        value: Box<Self>,
        key: RichKeyV1,
    },
    Conditional {
        condition: Box<RichConditionV1>,
        then_value: Box<Self>,
        else_value: Box<Self>,
    },
}

impl RichExpressionV1 {
    #[must_use]
    pub const fn literal(value: TypedValueV1) -> Self {
        Self::Literal(value)
    }

    #[must_use]
    pub const fn variable(name: RichNameV1) -> Self {
        Self::Variable(name)
    }
}

/// A closed conditional language with no implicit truthiness or effectful predicates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RichConditionV1 {
    Boolean(Box<RichExpressionV1>),
    IsSet(Box<RichExpressionV1>),
    Equal {
        left: Box<RichExpressionV1>,
        right: Box<RichExpressionV1>,
        negated: bool,
    },
    Not(Box<Self>),
    All(Vec<Self>),
    Any(Vec<Self>),
}

/// The source of a named variable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VariableSourceV1 {
    Input {
        optional: bool,
        default: Option<RichExpressionV1>,
    },
    Computed(RichExpressionV1),
}

/// A typed input or computed variable declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VariableDeclarationV1 {
    pub(crate) name: RichNameV1,
    pub(crate) value_type: TypedValueTypeV1,
    pub(crate) source: VariableSourceV1,
    pub(crate) range: SourceRangeV1,
}

impl VariableDeclarationV1 {
    #[must_use]
    pub const fn required(
        name: RichNameV1,
        value_type: TypedValueTypeV1,
        range: SourceRangeV1,
    ) -> Self {
        Self {
            name,
            value_type,
            source: VariableSourceV1::Input {
                optional: false,
                default: None,
            },
            range,
        }
    }

    #[must_use]
    pub const fn optional(
        name: RichNameV1,
        value_type: TypedValueTypeV1,
        range: SourceRangeV1,
    ) -> Self {
        Self {
            name,
            value_type,
            source: VariableSourceV1::Input {
                optional: true,
                default: None,
            },
            range,
        }
    }

    #[must_use]
    pub const fn defaulted(
        name: RichNameV1,
        value_type: TypedValueTypeV1,
        default: RichExpressionV1,
        range: SourceRangeV1,
    ) -> Self {
        Self {
            name,
            value_type,
            source: VariableSourceV1::Input {
                optional: false,
                default: Some(default),
            },
            range,
        }
    }

    #[must_use]
    pub const fn optional_defaulted(
        name: RichNameV1,
        value_type: TypedValueTypeV1,
        default: RichExpressionV1,
        range: SourceRangeV1,
    ) -> Self {
        Self {
            name,
            value_type,
            source: VariableSourceV1::Input {
                optional: true,
                default: Some(default),
            },
            range,
        }
    }

    #[must_use]
    pub const fn computed(
        name: RichNameV1,
        value_type: TypedValueTypeV1,
        expression: RichExpressionV1,
        range: SourceRangeV1,
    ) -> Self {
        Self {
            name,
            value_type,
            source: VariableSourceV1::Computed(expression),
            range,
        }
    }

    #[must_use]
    pub const fn is_input(&self) -> bool {
        matches!(self.source, VariableSourceV1::Input { .. })
    }

    #[must_use]
    pub const fn is_optional(&self) -> bool {
        matches!(self.source, VariableSourceV1::Input { optional: true, .. })
    }

    #[must_use]
    pub const fn default_expression(&self) -> Option<&RichExpressionV1> {
        match &self.source {
            VariableSourceV1::Input { default, .. } => default.as_ref(),
            VariableSourceV1::Computed(_) => None,
        }
    }

    #[must_use]
    pub const fn computed_expression(&self) -> Option<&RichExpressionV1> {
        match &self.source {
            VariableSourceV1::Computed(expression) => Some(expression),
            VariableSourceV1::Input { .. } => None,
        }
    }
}

impl VariableDeclarationV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub const fn value_type(&self) -> &TypedValueTypeV1 {
        &self.value_type
    }
    #[must_use]
    pub const fn range(&self) -> SourceRangeV1 {
        self.range
    }
}

/// A nonempty canonical path through record and collection keys.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RichValuePathV1(Vec<RichKeyV1>);

impl RichValuePathV1 {
    pub fn new(segments: Vec<RichKeyV1>) -> Result<Self, RichConfigErrorV1> {
        if segments.is_empty() {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "rich value path must not be empty",
            });
        }
        check_limit(
            "rich value path segments",
            segments.len(),
            MAX_RICH_VALUE_DEPTH,
        )?;
        Ok(Self(segments))
    }

    #[must_use]
    pub fn root(key: RichKeyV1) -> Self {
        Self(vec![key])
    }

    pub(crate) fn with_suffix(&self, key: RichKeyV1) -> Result<Self, RichConfigErrorV1> {
        let mut segments = self.0.clone();
        segments.push(key);
        Self::new(segments)
    }
}

impl RichValuePathV1 {
    #[must_use]
    pub fn segments(&self) -> &[RichKeyV1] {
        &self.0
    }
}

/// A mutation in an ordered patch block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatchOperationV1 {
    Set {
        path: RichValuePathV1,
        value: RichExpressionV1,
    },
    Unset {
        path: RichValuePathV1,
        optional: bool,
    },
    ListAppend {
        path: RichValuePathV1,
        value: RichExpressionV1,
    },
    CollectionInsert {
        path: RichValuePathV1,
        key: RichExpressionV1,
        value: RichExpressionV1,
    },
    CollectionReplace {
        path: RichValuePathV1,
        key: RichExpressionV1,
        value: RichExpressionV1,
    },
    CollectionRemove {
        path: RichValuePathV1,
        key: RichExpressionV1,
        optional: bool,
    },
    CollectionReplaceAll {
        path: RichValuePathV1,
        values: BTreeMap<RichKeyV1, RichExpressionV1>,
    },
}

/// A patch operation and its exact local source range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchStepV1 {
    pub(crate) operation: PatchOperationV1,
    pub(crate) range: SourceRangeV1,
}

impl PatchStepV1 {
    #[must_use]
    pub const fn new(operation: PatchOperationV1, range: SourceRangeV1) -> Self {
        Self { operation, range }
    }
}

impl PatchStepV1 {
    #[must_use]
    pub const fn operation(&self) -> &PatchOperationV1 {
        &self.operation
    }
    #[must_use]
    pub const fn range(&self) -> SourceRangeV1 {
        self.range
    }
}

/// Operations retained in their semantically significant declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedPatchV1 {
    pub(crate) steps: Vec<PatchStepV1>,
}

impl OrderedPatchV1 {
    pub fn new(steps: Vec<PatchStepV1>) -> Result<Self, RichConfigErrorV1> {
        check_limit("ordered patch operations", steps.len(), MAX_RICH_STATEMENTS)?;
        Ok(Self { steps })
    }
}

impl OrderedPatchV1 {
    #[must_use]
    pub fn steps(&self) -> &[PatchStepV1] {
        &self.steps
    }
}

/// A statement that contributes to the canonical document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RichStatementV1 {
    Emit {
        key: RichKeyV1,
        value: RichExpressionV1,
        range: SourceRangeV1,
    },
    Patch(OrderedPatchV1),
    Compose {
        fragment: RichNameV1,
        range: SourceRangeV1,
    },
    Conditional {
        condition: RichConditionV1,
        then_statements: Vec<Self>,
        else_statements: Vec<Self>,
        range: SourceRangeV1,
    },
    ForEach {
        value_binding: RichNameV1,
        key_binding: Option<RichNameV1>,
        iterable: RichExpressionV1,
        statements: Vec<Self>,
        range: SourceRangeV1,
    },
    Range {
        binding: RichNameV1,
        from: i64,
        through: i64,
        statements: Vec<Self>,
        range: SourceRangeV1,
    },
}

/// A named reusable sequence of rich statements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FragmentDeclarationV1 {
    pub(crate) name: RichNameV1,
    pub(crate) statements: Vec<RichStatementV1>,
    pub(crate) range: SourceRangeV1,
}

impl FragmentDeclarationV1 {
    pub fn new(
        name: RichNameV1,
        statements: Vec<RichStatementV1>,
        range: SourceRangeV1,
    ) -> Result<Self, RichConfigErrorV1> {
        check_limit("fragment statements", statements.len(), MAX_RICH_STATEMENTS)?;
        Ok(Self {
            name,
            statements,
            range,
        })
    }
}

impl FragmentDeclarationV1 {
    #[must_use]
    pub const fn name(&self) -> &RichNameV1 {
        &self.name
    }
    #[must_use]
    pub fn statements(&self) -> &[RichStatementV1] {
        &self.statements
    }
    #[must_use]
    pub const fn range(&self) -> SourceRangeV1 {
        self.range
    }
}

/// The semantic body built for a captured document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichDocumentBodyV1 {
    pub(crate) variables: BTreeMap<RichNameV1, VariableDeclarationV1>,
    pub(crate) fragments: BTreeMap<RichNameV1, FragmentDeclarationV1>,
    pub(crate) statements: Vec<RichStatementV1>,
}

impl RichDocumentBodyV1 {
    pub fn new(
        variables: Vec<VariableDeclarationV1>,
        fragments: Vec<FragmentDeclarationV1>,
        statements: Vec<RichStatementV1>,
    ) -> Result<Self, RichConfigErrorV1> {
        check_limit("rich variables", variables.len(), MAX_RICH_VARIABLES)?;
        check_limit("rich fragments", fragments.len(), MAX_RICH_FRAGMENTS)?;
        check_limit("rich statements", statements.len(), MAX_RICH_STATEMENTS)?;
        let mut variables_by_name = BTreeMap::new();
        for variable in variables {
            let name = variable.name.clone();
            insert_unique(&mut variables_by_name, name, variable, |name| {
                RichConfigErrorV1::DuplicateName {
                    resource: "variable",
                    name: name.into_inner(),
                }
            })?;
        }
        let mut fragments_by_name = BTreeMap::new();
        for fragment in fragments {
            let name = fragment.name.clone();
            insert_unique(&mut fragments_by_name, name, fragment, |name| {
                RichConfigErrorV1::DuplicateName {
                    resource: "fragment",
                    name: name.into_inner(),
                }
            })?;
        }
        Ok(Self {
            variables: variables_by_name,
            fragments: fragments_by_name,
            statements,
        })
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self {
            variables: BTreeMap::new(),
            fragments: BTreeMap::new(),
            statements: Vec::new(),
        }
    }
}

impl RichDocumentBodyV1 {
    #[must_use]
    pub const fn variables(&self) -> &BTreeMap<RichNameV1, VariableDeclarationV1> {
        &self.variables
    }
    #[must_use]
    pub const fn fragments(&self) -> &BTreeMap<RichNameV1, FragmentDeclarationV1> {
        &self.fragments
    }
    #[must_use]
    pub fn statements(&self) -> &[RichStatementV1] {
        &self.statements
    }
}

/// An unresolved include interpreted only against the supplied authority graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichIncludeReferenceV1 {
    path: PackPath,
    dependency: Option<Alias>,
    range: SourceRangeV1,
}

impl RichIncludeReferenceV1 {
    #[must_use]
    pub const fn new(path: PackPath, dependency: Option<Alias>, range: SourceRangeV1) -> Self {
        Self {
            path,
            dependency,
            range,
        }
    }
}

impl RichIncludeReferenceV1 {
    #[must_use]
    pub const fn path(&self) -> &PackPath {
        &self.path
    }
    #[must_use]
    pub const fn dependency(&self) -> Option<&Alias> {
        self.dependency.as_ref()
    }
    #[must_use]
    pub const fn range(&self) -> SourceRangeV1 {
        self.range
    }
}

/// An unresolved exported-module reference in a pack's private dependency scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichModuleReferenceV1 {
    module: ContributionName,
    dependency: Option<Alias>,
    range: SourceRangeV1,
}

impl RichModuleReferenceV1 {
    #[must_use]
    pub const fn new(
        module: ContributionName,
        dependency: Option<Alias>,
        range: SourceRangeV1,
    ) -> Self {
        Self {
            module,
            dependency,
            range,
        }
    }
}

impl RichModuleReferenceV1 {
    #[must_use]
    pub const fn module(&self) -> &ContributionName {
        &self.module
    }
    #[must_use]
    pub const fn dependency(&self) -> Option<&Alias> {
        self.dependency.as_ref()
    }
    #[must_use]
    pub const fn range(&self) -> SourceRangeV1 {
        self.range
    }
}

/// The semantic kind of an exact document-composition edge.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CapturedDocumentEdgeKindV1 {
    Include,
    Module { name: ContributionName },
}

/// An include or module edge with its exact resolved target authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedIncludeV1 {
    target: CapturedDocumentIdV1,
    dependency: Option<Alias>,
    kind: CapturedDocumentEdgeKindV1,
    range: SourceRangeV1,
}

impl CapturedIncludeV1 {
    #[must_use]
    pub const fn new(target: CapturedDocumentIdV1, range: SourceRangeV1) -> Self {
        Self {
            target,
            dependency: None,
            kind: CapturedDocumentEdgeKindV1::Include,
            range,
        }
    }

    #[must_use]
    pub const fn direct_include(
        target: CapturedDocumentIdV1,
        dependency: Alias,
        range: SourceRangeV1,
    ) -> Self {
        Self {
            target,
            dependency: Some(dependency),
            kind: CapturedDocumentEdgeKindV1::Include,
            range,
        }
    }

    #[must_use]
    pub const fn module(
        target: CapturedDocumentIdV1,
        name: ContributionName,
        dependency: Option<Alias>,
        range: SourceRangeV1,
    ) -> Self {
        Self {
            target,
            dependency,
            kind: CapturedDocumentEdgeKindV1::Module { name },
            range,
        }
    }
}

impl CapturedIncludeV1 {
    #[must_use]
    pub const fn target(&self) -> &CapturedDocumentIdV1 {
        &self.target
    }
    #[must_use]
    pub const fn dependency(&self) -> Option<&Alias> {
        self.dependency.as_ref()
    }
    #[must_use]
    pub const fn kind(&self) -> &CapturedDocumentEdgeKindV1 {
        &self.kind
    }
    #[must_use]
    pub const fn range(&self) -> SourceRangeV1 {
        self.range
    }
}

/// Exact captured bytes and their constructed semantic body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedConfigDocumentV1 {
    id: CapturedDocumentIdV1,
    bytes: Vec<u8>,
    digest: Digest,
    includes: Vec<CapturedIncludeV1>,
    body: RichDocumentBodyV1,
}

impl CapturedConfigDocumentV1 {
    pub fn new(
        id: CapturedDocumentIdV1,
        bytes: impl Into<Vec<u8>>,
        includes: Vec<CapturedIncludeV1>,
        body: RichDocumentBodyV1,
    ) -> Result<Self, RichConfigErrorV1> {
        let bytes = bytes.into();
        check_limit(
            "captured document bytes",
            bytes.len(),
            MAX_CONFIG_DOCUMENT_BYTES,
        )?;
        check_limit(
            "includes per document",
            includes.len(),
            MAX_RICH_INCLUDES_PER_DOCUMENT,
        )?;
        let mut targets = BTreeSet::new();
        for include in &includes {
            insert_unique_key(&mut targets, include.target.clone(), |target| {
                RichConfigErrorV1::DuplicateName {
                    resource: "include target",
                    name: target.to_string(),
                }
            })?;
        }
        let digest = Digest::sha256(&bytes);
        Ok(Self {
            id,
            bytes,
            digest,
            includes,
            body,
        })
    }
}

impl CapturedConfigDocumentV1 {
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
    pub fn includes(&self) -> &[CapturedIncludeV1] {
        &self.includes
    }
    #[must_use]
    pub const fn body(&self) -> &RichDocumentBodyV1 {
        &self.body
    }
}

/// The complete finite document universe available to rich include evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedDocumentSetV1 {
    pub(crate) authorities: CapturedAuthorityGraphV1,
    pub(crate) documents: BTreeMap<CapturedDocumentIdV1, CapturedConfigDocumentV1>,
}

impl CapturedDocumentSetV1 {
    pub fn new(
        authorities: CapturedAuthorityGraphV1,
        documents: Vec<CapturedConfigDocumentV1>,
    ) -> Result<Self, RichConfigErrorV1> {
        check_limit("captured documents", documents.len(), MAX_RICH_DOCUMENTS)?;
        let total_bytes = documents.iter().fold(0_usize, |total, document| {
            total.saturating_add(document.bytes.len())
        });
        check_limit(
            "total captured document bytes",
            total_bytes,
            MAX_RICH_TOTAL_CAPTURED_BYTES,
        )?;
        let total_includes = documents.iter().fold(0_usize, |total, document| {
            total.saturating_add(document.includes.len())
        });
        check_limit(
            "total captured include edges",
            total_includes,
            MAX_RICH_TOTAL_INCLUDES,
        )?;
        let mut by_id = BTreeMap::new();
        for document in documents {
            let id = document.id.clone();
            if !authorities.authorities.contains_key(id.authority()) {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "captured document claims an authority outside the locked graph",
                });
            }
            for edge in document.includes() {
                authorities.validate_edge(&id, edge)?;
            }
            insert_unique(&mut by_id, id, document, |id| {
                RichConfigErrorV1::DuplicateName {
                    resource: "captured document",
                    name: id.to_string(),
                }
            })?;
        }
        Ok(Self {
            authorities,
            documents: by_id,
        })
    }
}

impl CapturedDocumentSetV1 {
    #[must_use]
    pub const fn authorities(&self) -> &CapturedAuthorityGraphV1 {
        &self.authorities
    }
    #[must_use]
    pub const fn documents(&self) -> &BTreeMap<CapturedDocumentIdV1, CapturedConfigDocumentV1> {
        &self.documents
    }
}

/// Evaluation context retained by each source provenance record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvaluationFrameV1 {
    Fragment(RichNameV1),
    Conditional { then_branch: bool },
    Loop { binding: RichNameV1, iteration: u32 },
}

/// The semantic action represented by a provenance record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProvenanceOperationV1 {
    VariableSupplied,
    VariableDefault,
    VariableOptionalAbsent,
    VariableComputed,
    Emit,
    Patch { operation: u32 },
}

/// A deterministic, sequence-numbered source contribution.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProvenanceRecordV1 {
    sequence: u64,
    location: SourceLocationV1,
    operation: ProvenanceOperationV1,
    frames: Vec<EvaluationFrameV1>,
}

impl ProvenanceRecordV1 {
    pub(crate) fn new(
        sequence: u64,
        location: SourceLocationV1,
        operation: ProvenanceOperationV1,
        frames: Vec<EvaluationFrameV1>,
    ) -> Self {
        Self {
            sequence,
            location,
            operation,
            frames,
        }
    }
}

impl ProvenanceRecordV1 {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn location(&self) -> &SourceLocationV1 {
        &self.location
    }
    #[must_use]
    pub const fn operation(&self) -> &ProvenanceOperationV1 {
        &self.operation
    }
    #[must_use]
    pub fn frames(&self) -> &[EvaluationFrameV1] {
        &self.frames
    }
}

/// Provenance for a validated include edge.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IncludeProvenanceV1 {
    source: SourceLocationV1,
    target: CapturedDocumentIdV1,
    target_digest: Digest,
    dependency: Option<Alias>,
    kind: CapturedDocumentEdgeKindV1,
}

impl IncludeProvenanceV1 {
    pub(crate) const fn new(
        source: SourceLocationV1,
        target: CapturedDocumentIdV1,
        target_digest: Digest,
        dependency: Option<Alias>,
        kind: CapturedDocumentEdgeKindV1,
    ) -> Self {
        Self {
            source,
            target,
            target_digest,
            dependency,
            kind,
        }
    }
}

impl IncludeProvenanceV1 {
    #[must_use]
    pub const fn source(&self) -> &SourceLocationV1 {
        &self.source
    }
    #[must_use]
    pub const fn target(&self) -> &CapturedDocumentIdV1 {
        &self.target
    }
    #[must_use]
    pub const fn target_digest(&self) -> &Digest {
        &self.target_digest
    }
    #[must_use]
    pub const fn dependency(&self) -> Option<&Alias> {
        self.dependency.as_ref()
    }
    #[must_use]
    pub const fn kind(&self) -> &CapturedDocumentEdgeKindV1 {
        &self.kind
    }
}

/// Canonical typed document consumed by planning and every format transform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTypedDocumentV1 {
    version: u32,
    root: TypedValueV1,
    source_documents: BTreeMap<CapturedDocumentIdV1, CapturedSourceIdentityV1>,
    includes: Vec<IncludeProvenanceV1>,
    provenance: BTreeMap<RichValuePathV1, Vec<ProvenanceRecordV1>>,
}

impl CanonicalTypedDocumentV1 {
    pub fn new(root: TypedValueV1) -> Result<Self, RichConfigErrorV1> {
        if root.kind() != TypedValueKindV1::Record {
            return Err(RichConfigErrorV1::TypeMismatch {
                expected: "record document root".to_owned(),
                actual: root.kind().as_str(),
            });
        }
        root.validate()?;
        Ok(Self {
            version: RICH_CONFIG_IR_VERSION,
            root,
            source_documents: BTreeMap::new(),
            includes: Vec::new(),
            provenance: BTreeMap::new(),
        })
    }

    pub(crate) fn evaluated(
        root: TypedValueV1,
        source_documents: BTreeMap<CapturedDocumentIdV1, CapturedSourceIdentityV1>,
        includes: Vec<IncludeProvenanceV1>,
        provenance: BTreeMap<RichValuePathV1, Vec<ProvenanceRecordV1>>,
    ) -> Result<Self, RichConfigErrorV1> {
        let document = Self {
            version: RICH_CONFIG_IR_VERSION,
            root,
            source_documents,
            includes,
            provenance,
        };
        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<(), RichConfigErrorV1> {
        if self.version != RICH_CONFIG_IR_VERSION {
            return Err(RichConfigErrorV1::InvalidValue {
                reason: "unsupported canonical typed document version",
            });
        }
        if self.root.kind() != TypedValueKindV1::Record {
            return Err(RichConfigErrorV1::TypeMismatch {
                expected: "record document root".to_owned(),
                actual: self.root.kind().as_str(),
            });
        }
        self.root.validate()?;
        check_limit(
            "canonical source documents",
            self.source_documents.len(),
            MAX_RICH_DOCUMENTS,
        )?;
        check_limit(
            "canonical include edges",
            self.includes.len(),
            MAX_RICH_TOTAL_INCLUDES,
        )?;
        for include in &self.includes {
            let Some(source_identity) = self.source_documents.get(include.source.document()) else {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "include provenance references an unknown source document",
                });
            };
            if u64::from(include.source.range().end()) > source_identity.byte_len {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "include provenance range exceeds its captured source bytes",
                });
            }
            let Some(target_identity) = self.source_documents.get(&include.target) else {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "include provenance references an unknown target document",
                });
            };
            if target_identity.digest != include.target_digest {
                return Err(RichConfigErrorV1::InvalidValue {
                    reason: "include provenance target digest does not match its source record",
                });
            }
        }
        let record_count = self.provenance.values().fold(0_usize, |total, records| {
            total.saturating_add(records.len())
        });
        check_limit(
            "canonical provenance records",
            record_count,
            MAX_RICH_PROVENANCE_RECORDS,
        )?;
        let mut sequences = BTreeSet::new();
        for records in self.provenance.values() {
            let mut previous = None;
            for record in records {
                let Some(source_identity) = self.source_documents.get(record.location.document())
                else {
                    return Err(RichConfigErrorV1::InvalidValue {
                        reason: "provenance references an unknown source document",
                    });
                };
                if u64::from(record.location.range().end()) > source_identity.byte_len {
                    return Err(RichConfigErrorV1::InvalidValue {
                        reason: "provenance range exceeds its captured source bytes",
                    });
                }
                if previous.is_some_and(|sequence| sequence >= record.sequence) {
                    return Err(RichConfigErrorV1::InvalidValue {
                        reason: "provenance for one value path is not sequence ordered",
                    });
                }
                if !sequences.insert(record.sequence) {
                    return Err(RichConfigErrorV1::InvalidValue {
                        reason: "provenance sequence number is duplicated",
                    });
                }
                check_limit(
                    "provenance evaluation frames",
                    record.frames.len(),
                    MAX_RICH_VALUE_DEPTH,
                )?;
                previous = Some(record.sequence);
            }
        }
        Ok(())
    }
}

impl CanonicalTypedDocumentV1 {
    #[must_use]
    pub const fn source_documents(
        &self,
    ) -> &BTreeMap<CapturedDocumentIdV1, CapturedSourceIdentityV1> {
        &self.source_documents
    }
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
    #[must_use]
    pub const fn root(&self) -> &TypedValueV1 {
        &self.root
    }
    #[must_use]
    pub fn includes(&self) -> &[IncludeProvenanceV1] {
        &self.includes
    }
    #[must_use]
    pub const fn provenance(&self) -> &BTreeMap<RichValuePathV1, Vec<ProvenanceRecordV1>> {
        &self.provenance
    }
}
