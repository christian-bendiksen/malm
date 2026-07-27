//! Parsed workspace declarations and their source spans.

use crate::lang::diag::Span;
use crate::lang::value::{Type, Value};
use kdl::KdlNode;
use std::path::PathBuf;

/// Workspace declarations before resolution.
#[derive(Debug, Default)]
pub struct ParsedWorkspace {
    pub modules: Vec<ModuleDecl>,
    pub extensions: Vec<ExtendModule>,
    pub profiles: Vec<ProfileDecl>,
    pub profile_extensions: Vec<ExtendProfile>,
    pub slots: Vec<SlotDecl>,
    /// `global.*` design tokens (typed scalars).
    pub globals: Vec<GlobalVar>,
}

#[derive(Debug)]
pub struct GlobalVar {
    pub name: String,
    pub value: Value,
    /// Explicitly replaces an earlier declaration of the same global.
    pub override_existing: bool,
    #[allow(dead_code)]
    pub span: Span,
    /// Human-readable source path used in provenance reports.
    #[allow(dead_code)]
    pub origin: String,
}

#[derive(Debug)]
pub struct SlotDecl {
    pub name: String,
    pub max: SlotMax,
    #[allow(dead_code)]
    pub description: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy)]
pub enum SlotMax {
    Max(usize),
    Unlimited,
}

impl SlotMax {
    pub fn permits(self, count: usize) -> bool {
        match self {
            Self::Max(n) => count <= n,
            Self::Unlimited => true,
        }
    }

    pub fn label(self) -> String {
        match self {
            Self::Max(n) => n.to_string(),
            Self::Unlimited => "many".to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct ModuleDecl {
    pub name: String,
    pub description: Option<String>,
    pub slot: Option<String>,
    /// Module-scoped declarations retained only until type resolution.
    pub types: Vec<NamedTypeDecl>,
    pub requires: Vec<RequirementNode>,
    pub inputs: Vec<InputDecl>,
    pub fragments: Vec<FragmentDecl>,
    pub outputs: Vec<OutputNode>,
    pub span: Span,
    /// Directory of the declaring file, used to resolve `./` sources.
    #[allow(dead_code)]
    pub dir: PathBuf,
}

/// One module-scoped enum or record declaration. Its body may contain
/// parse-time [`Type::Named`] references; resolution erases them.
#[derive(Debug, Clone)]
pub struct NamedTypeDecl {
    pub name: String,
    pub ty: Type,
    pub span: Span,
}

/// An `extend-module "name" { ... }` declaration from an included file.
#[derive(Debug)]
pub struct ExtendModule {
    pub module: String,
    pub requires: Vec<RequirementNode>,
    pub inputs: Vec<InputDecl>,
    pub fragments: Vec<FragmentDecl>,
    pub outputs: Vec<OutputNode>,
    pub span: Span,
    #[allow(dead_code)]
    pub dir: PathBuf,
}

#[derive(Debug)]
pub struct Requirement {
    /// Requirement category evaluated by the host against the live system.
    #[allow(dead_code)]
    pub kind: RequirementKind,
    #[allow(dead_code)]
    pub subject: String,
    #[allow(dead_code)]
    pub span: Span,
}

/// A requirement, optionally guarded by an output-style condition.
#[derive(Debug)]
pub enum RequirementNode {
    /// The payload is read by the host-side `doctor` report.
    Requirement(#[allow(dead_code)] Requirement),
    When(WhenBlock<RequirementNode>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementKind {
    Command,
    File,
    Feature,
}

impl RequirementKind {
    /// Returns the category name used in host reports.
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::File => "file",
            Self::Feature => "feature",
        }
    }
}

/// A typed public input. `name` is module-scoped (no module prefix).
#[derive(Debug)]
pub struct InputDecl {
    pub name: String,
    pub ty: Type,
    /// Present when the input declares a default. Optionals without a
    /// default resolve to `Null`; non-optionals without a default are
    /// required.
    pub default: Option<Value>,
    pub span: Span,
    /// Span of the default value if given (for diagnostics).
    pub default_span: Option<Span>,
    /// A computed default template (`default=(f)"..."` or
    /// `default (f)"..."`). Evaluated at profile-checking time against the
    /// resolved scope after profile overrides and patches have been
    /// applied. See the "Computed Defaults" section in
    /// `docs/authoring-types.md`.
    pub computed_default: Option<String>,
    pub computed_default_span: Option<Span>,
}

impl InputDecl {
    pub fn required(&self) -> bool {
        self.default.is_none() && self.computed_default.is_none() && !self.ty.is_optional()
    }
}

/// A profile-replaceable native-file slot.
#[derive(Debug)]
pub struct FragmentDecl {
    pub name: String,
    /// Declared format of the composed fragment ("kdl-v1", "kdl-v2",
    /// "text", or a known artifact format like "hypr").
    pub format: String,
    pub cardinality: FragmentCardinality,
    /// Default source files, resolved relative to `dir`.
    pub defaults: Vec<FragmentSource>,
    pub span: Span,
    #[allow(dead_code)]
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentCardinality {
    One,
    Many,
}

/// A fragment source and the directory it resolves from.
#[derive(Debug, Clone)]
pub struct FragmentSource {
    pub path: String,
    pub base_dir: PathBuf,
    pub span: Span,
}

/// A node inside `outputs { }`: either a concrete output declaration or a
/// structural condition wrapping more output nodes.
#[derive(Debug)]
pub enum OutputNode {
    KdlConfig(KdlConfigOutput),
    ConfigFile(crate::lang::config_file::ConfigFileOutput),
    Render(crate::lang::render::RenderOutput),
    File(FileOutput),
    Dir(DirOutput),
    Symlink(SymlinkOutput),
    When(WhenBlock<OutputNode>),
    Each(EachBlock<OutputNode>),
    Range(RangeBlock<OutputNode>),
}

/// A structural condition with an optional immediately following `@else`.
#[derive(Debug, Clone)]
pub struct WhenBlock<T> {
    pub predicate: Predicate,
    pub then: Vec<T>,
    pub otherwise: Vec<T>,
    pub span: Span,
}

/// The predicate selected by a short condition node.
#[derive(Debug, Clone)]
pub enum Predicate {
    /// `@if "name"` requires bool.
    Test(Ref),
    /// `@if-present "name"` requires optional<T>.
    Set(Ref),
    /// `@if-nonempty "name"` requires a list or collection.
    NonEmpty(Ref),
    /// `@if "name" is="value"` / `is-not="value"` scalar equality.
    Eq {
        reference: Ref,
        expected: Value,
        negated: bool,
    },
}

impl Predicate {
    pub fn reference(&self) -> &Ref {
        match self {
            Self::Test(r) | Self::Set(r) | Self::NonEmpty(r) => r,
            Self::Eq { reference, .. } => reference,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Test(_) => "@if",
            Self::Set(_) => "@if-present",
            Self::NonEmpty(_) => "@if-nonempty",
            Self::Eq { negated: false, .. } => "@if is=",
            Self::Eq { negated: true, .. } => "@if is-not=",
        }
    }

    /// Evaluates the predicate against an already-looked-up value. A missing
    /// value behaves like an absent optional for presence and equality tests.
    /// `None` means the value's shape cannot satisfy this predicate.
    pub fn eval(&self, value: Option<&Value>) -> Option<bool> {
        match (self, value) {
            (Self::Test(_), Some(Value::Bool(value))) => Some(*value),
            (Self::Set(_), value) => Some(value.is_some_and(|value| !value.is_null())),
            (Self::NonEmpty(_), Some(Value::List(values))) => Some(!values.is_empty()),
            (Self::NonEmpty(_), Some(Value::Collection(values))) => Some(!values.is_empty()),
            (
                Self::Eq {
                    expected, negated, ..
                },
                value,
            ) => {
                let equal = value.is_some_and(|value| value.semantic_eq(expected));
                Some(equal != *negated)
            }
            _ => None,
        }
    }
}

/// A `(ref)"name"` reference, possibly dotted for record fields
/// (`emergency-entry.label`).
#[derive(Debug, Clone)]
pub struct Ref {
    pub name: String,
    pub span: Span,
}

/// Structural `@for-each "binding" in="list"`.
#[derive(Debug, Clone)]
pub struct EachBlock<T> {
    pub binding: String,
    pub source: Ref,
    pub body: Vec<T>,
    pub span: Span,
}

/// Structural `@for-range "binding" from=N through=M`.
#[derive(Debug, Clone)]
pub struct RangeBlock<T> {
    pub binding: String,
    pub from: i64,
    pub through: i64,
    pub body: Vec<T>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdlDialect {
    V1,
    V2,
}

impl KdlDialect {
    pub fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

#[derive(Debug)]
pub struct KdlConfigOutput {
    pub to: String,
    pub dialect: KdlDialect,
    pub body: KdlConfigBody,
    pub transforms: Vec<String>,
    pub span: Span,
}

/// Inline target KDL with short controls interpreted during expansion.
#[derive(Debug)]
pub enum KdlConfigBody {
    Document {
        nodes: Vec<KdlNode>,
        span: Span,
        file: crate::lang::diag::FileId,
    },
}

#[derive(Debug)]
pub struct FileOutput {
    pub source: String,
    pub to: String,
    pub optional: bool,
    /// Deploy the file with an executable mode. Declared in config because
    /// captured pack files are pure bytes and carry no filesystem modes.
    pub executable: bool,
    pub on_conflict: ConflictPolicy,
    pub span: Span,
    pub dir: PathBuf,
}

#[derive(Debug)]
pub struct DirOutput {
    pub source: String,
    pub to: Option<String>,
    pub optional: bool,
    /// Deploy every file in the tree with an executable mode. Declared in
    /// config because captured pack files are pure bytes without modes.
    pub executable: bool,
    pub on_conflict: ConflictPolicy,
    pub ignore: Vec<String>,
    pub span: Span,
    pub dir: PathBuf,
}

#[derive(Debug)]
pub struct SymlinkOutput {
    pub source: SymlinkSource,
    pub to: String,
    pub optional: bool,
    pub if_missing: MissingSourcePolicy,
    #[allow(dead_code)]
    pub span: Span,
}

/// A symlink source: a literal absolute/`~/` path, or a reference to a
/// path-typed input (`symlink source=(ref)"theme-ref" ...`).
#[derive(Debug)]
pub enum SymlinkSource {
    Literal(String),
    Ref(Ref),
}

/// What to do when a deployed destination already exists unmanaged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConflictPolicy {
    Fail,
    #[default]
    Backup,
}

/// Whether an output's source file may be absent at evaluation time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MissingSourcePolicy {
    #[default]
    RequireSource,
    AllowMissingUntilRendered,
}

impl MissingSourcePolicy {
    /// Returns whether plan lowering may accept a missing symlink target.
    #[allow(dead_code)]
    pub fn allow_missing_source(self) -> bool {
        matches!(self, Self::AllowMissingUntilRendered)
    }
}

#[derive(Debug)]
pub struct ProfileDecl {
    pub name: String,
    /// Abstract profiles are reusable inheritance layers. They are checked
    /// like ordinary profiles but cannot be selected for deployment/rendering.
    pub abstract_: bool,
    pub extends: Vec<(String, Span)>,
    pub items: Vec<ProfileItem>,
    pub span: Span,
    #[allow(dead_code)] // Fragment sources carry their own base directories.
    pub dir: PathBuf,
}

/// An explicit additional layer for an existing profile.
#[derive(Debug)]
pub struct ExtendProfile {
    pub profile: String,
    pub extends: Vec<(String, Span)>,
    pub items: Vec<ProfileItem>,
    pub span: Span,
}

/// One operation per node: `use` activates a module, `replace` swaps a slot
/// provider.
#[derive(Debug)]
pub enum ProfileItem {
    Use(UseDecl),
    Replace(ReplaceDecl),
}

#[derive(Debug)]
pub struct UseDecl {
    pub module: String,
    pub alias: Option<String>,
    pub config: InstanceConfig,
    pub span: Span,
}

#[derive(Debug)]
pub struct ReplaceDecl {
    pub slot: String,
    pub module: String,
    pub alias: Option<String>,
    pub config: InstanceConfig,
    pub span: Span,
}

/// The per-instance configuration a profile applies: input overrides,
/// fragment replacements, and an ordered stream of record-field and collection
/// patches. Field (`set`/`unset`) and collection
/// (`replace`/`append`/`remove`/`replace-all`) patches retain their authored
/// order within each profile layer.
#[derive(Debug, Default)]
pub struct InstanceConfig {
    pub with: Vec<WithEntry>,
    pub fragments: Vec<FragmentOp>,
    pub patch_entries: Vec<PatchEntry>,
}

/// One entry in an instance's ordered patch stream.
///
/// The stream preserves the interleaving of field and collection patches in a
/// `patch { }` block. Each patch observes all earlier patches in that block.
#[derive(Debug, Clone)]
pub enum PatchEntry {
    /// `patch { set "input.field[..subfield]" <value> }` /
    /// `patch { unset "input.field[..subfield]" }`. The path may be dotted
    /// recursively to navigate through nested record fields.
    Field(SetPatch),
    /// `patch { collection "name" { ... } }`.
    Collection(CollectionPatch),
}

/// `patch { set "input.field1.field2..." <value> }` /
/// `patch { unset "input.field1.field2..." }`: assign or clear a field of a
/// record input without replacing the whole record. The dotted path may
/// traverse any number of nested record (or variant) fields; each intermediate
/// segment must already be present (set through defaults or `with`).
/// `value: None` is `unset` (optional fields only).
#[derive(Debug, Clone)]
pub struct SetPatch {
    pub path: String,
    pub value: Option<Value>,
    pub span: Span,
}

#[derive(Debug)]
pub struct WithEntry {
    pub name: String,
    /// `Value::Null` clears an optional.
    pub value: Value,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum FragmentOp {
    Replace(FragmentOpBody),
    Append(FragmentOpBody),
}

#[derive(Debug, Clone)]
pub struct FragmentOpBody {
    pub fragment: String,
    pub source: FragmentSource,
    pub span: Span,
}

/// A `patch { collection "bindings" { ... } }` declaration.
#[derive(Debug, Clone)]
pub struct CollectionPatch {
    pub collection: String,
    pub ops: Vec<PatchOp>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum PatchOp {
    /// `replace "key" { ... }` requires an existing key and preserves its position.
    Replace {
        key: String,
        value: Value,
        span: Span,
    },
    /// `append "key" { ... }` requires a new key.
    Append {
        key: String,
        value: Value,
        span: Span,
    },
    /// `remove "key"` requires the key unless `optional=#true`.
    Remove {
        key: String,
        optional: bool,
        span: Span,
    },
    /// `replace-all { item "key" { ... } ... }` explicitly replaces everything.
    ReplaceAll {
        items: Vec<(String, Value, Span)>,
        span: Span,
    },
}
