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
    /// Human-readable origin ("malm.kdl", "machines/laptop-4k.kdl", …).
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

// Modules

#[derive(Debug)]
pub struct ModuleDecl {
    pub name: String,
    pub description: Option<String>,
    pub slot: Option<String>,
    pub requires: Vec<RequirementNode>,
    pub inputs: Vec<InputDecl>,
    pub fragments: Vec<FragmentDecl>,
    pub outputs: Vec<OutputNode>,
    pub span: Span,
    /// Directory of the file that declared the module (for `./…` sources).
    #[allow(dead_code)]
    pub dir: PathBuf,
}

/// `extend-module "name" { … }` from an included file.
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
    pub kind: RequirementKind,
    pub subject: String,
    #[allow(dead_code)]
    pub span: Span,
}

/// A requirement, optionally guarded by an output-style condition.
#[derive(Debug)]
pub enum RequirementNode {
    Requirement(Requirement),
    When(WhenBlock<RequirementNode>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementKind {
    Command,
    File,
    Feature,
}

impl RequirementKind {
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
}

impl InputDecl {
    pub fn required(&self) -> bool {
        self.default.is_none()
            && !self.ty.is_optional()
            && !matches!(self.ty, Type::List(_) | Type::Collection(_))
    }
}

/// A profile-replaceable native-file slot.
#[derive(Debug)]
pub struct FragmentDecl {
    pub name: String,
    /// Declared format of the composed fragment ("kdl-v1", "kdl-v2",
    /// "text", or an artifact-validator name like "hypr").
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

// Outputs

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

/// A structural condition with an optional trailing `else`.
#[derive(Debug)]
pub struct WhenBlock<T> {
    pub predicate: Predicate,
    pub then: Vec<T>,
    pub otherwise: Vec<T>,
    pub span: Span,
}

/// The predicate selected by a short condition node.
#[derive(Debug)]
pub enum Predicate {
    /// `when "name"` requires bool.
    Test(Ref),
    /// `when-set "name"` requires optional<T>.
    Set(Ref),
    /// `when-nonempty "name"` requires a list or collection.
    NonEmpty(Ref),
    /// `@when "name" is="value"` / `is-not="value"` scalar equality.
    /// Unsigiled controls do not support equality.
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
            Self::Test(_) => "when",
            Self::Set(_) => "when-set",
            Self::NonEmpty(_) => "when-nonempty",
            Self::Eq { negated: false, .. } => "when is=",
            Self::Eq { negated: true, .. } => "when is-not=",
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

/// Structural `each "binding" in="list"`.
#[derive(Debug)]
pub struct EachBlock<T> {
    pub binding: String,
    pub source: Ref,
    pub body: Vec<T>,
    pub span: Span,
}

/// Structural `range "binding" from=N through=M`.
#[derive(Debug)]
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
    pub validate: Option<String>,
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
    pub on_conflict: ConflictPolicy,
    pub span: Span,
    pub dir: PathBuf,
}

#[derive(Debug)]
pub struct DirOutput {
    pub source: String,
    pub to: Option<String>,
    pub optional: bool,
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
/// path-typed input (`symlink source=(ref)"theme-ref" …`).
#[derive(Debug)]
pub enum SymlinkSource {
    Literal(String),
    Ref(Ref),
}

pub use crate::config::{ConflictPolicy, MissingSourcePolicy};

// Profiles

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
/// fragment replacements, collection patches, and record-field patches.
#[derive(Debug, Default)]
pub struct InstanceConfig {
    pub with: Vec<WithEntry>,
    pub fragments: Vec<FragmentOp>,
    pub patches: Vec<CollectionPatch>,
    pub sets: Vec<SetPatch>,
}

/// `patch { set "input.field" <value> }` / `patch { unset "input.field" }`:
/// assign or clear one field of a record input without replacing the whole
/// record. `value: None` is `unset` (optional fields only).
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

#[derive(Debug)]
pub enum FragmentOp {
    Replace(FragmentOpBody),
    Append(FragmentOpBody),
}

#[derive(Debug)]
pub struct FragmentOpBody {
    pub fragment: String,
    pub source: FragmentSource,
    pub span: Span,
}

/// `patch { collection "bindings" { … } }`.
#[derive(Debug)]
pub struct CollectionPatch {
    pub collection: String,
    pub ops: Vec<PatchOp>,
    pub span: Span,
}

#[derive(Debug)]
pub enum PatchOp {
    /// `replace "key" { … }` requires an existing key and preserves its position.
    Replace {
        key: String,
        value: Value,
        span: Span,
    },
    /// `append "key" { … }` requires a new key.
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
    /// `replace-all { item "key" { … } … }` explicitly replaces everything.
    ReplaceAll {
        items: Vec<(String, Value, Span)>,
        span: Span,
    },
}
