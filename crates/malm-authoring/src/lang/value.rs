//! Typed values retained until artifact serialization.

use crate::lang::diag::{FileId, Span};
use kdl::KdlDocument;
use std::collections::BTreeMap;
use std::fmt;

/// A value's declared type. `Optional` wraps a scalar/aggregate type;
/// nesting optionals is not allowed.
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Bool,
    Int,
    Float,
    String,
    Path,
    /// A closed set of string values.
    Enum(Vec<String>),
    List(Box<Type>),
    Record(RecordSchema),
    /// A keyed collection and the payload type shared by its items.
    Collection(Box<Type>),
    KdlDocument,
    Optional(Box<Type>),
    /// Parse-time reference to a module-scoped type. Resolution removes every
    /// occurrence before type checking or expansion.
    Named(String),
    /// A closed discriminated union. After value coercion a variant lowers to
    /// `Value::Record({ discriminator: <case-name>, ...case-fields })`.
    Variant(VariantSchema),
    /// A named refinement over a scalar base type. Coercion delegates to the
    /// base type and then validates the result against the declared
    /// constraints (`min`/`max` numeric ranges, item-count bounds for
    /// `list<string>`, or string `format` patterns). The lowered value is
    /// indistinguishable from the base type's canonical value.
    Refine(RefineSchema),
    /// A string-keyed map of one payload type. Behaviorally identical to
    /// [`Type::Collection`] except map keys are canonically sorted by string
    /// comparison at coercion time.
    Map(Box<Type>),
    /// A fixed-arity sequence of heterogeneous types. Lowers to a
    /// `Value::List` whose length matches the declared element count, with
    /// per-position validation against the corresponding type.
    Tuple(Vec<Type>),
    /// An ordered, deduplicated sequence of one scalar element type. Lowers to
    /// a `Value::List` whose entries are unique and structurally sorted.
    Set(Box<Type>),
}

/// Runtime value shape after schema-only wrappers have been removed.
/// Static checks use this rather than restating how refinements, variants,
/// maps, tuples, and sets are represented by [`Value`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum LoweredType<'a> {
    Bool,
    Int,
    Float,
    String,
    Path,
    Enum(&'a [String]),
    List(LoweredList<'a>),
    Record,
    Collection(&'a Type),
    KdlDocument,
    Optional,
    Named,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LoweredList<'a> {
    Homogeneous(&'a Type),
    Tuple(&'a [Type]),
}

impl LoweredType<'_> {
    pub(crate) fn is_scalar(self) -> bool {
        matches!(
            self,
            Self::Bool | Self::Int | Self::Float | Self::String | Self::Path | Self::Enum(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordSchema {
    pub fields: Vec<FieldSchema>,
}

/// A named scalar type with optional validation constraints. Refinements lower
/// to the base type's canonical value; the schema is retained only for type
/// checking and reference lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct RefineSchema {
    /// The refinement's module-scoped name.
    pub name: String,
    /// The base type this refinement wraps. Must be one of the scalar
    /// built-ins (`bool`, `int`, `float`, `string`, `path`) or
    /// `list<string>`.
    pub base: Box<Type>,
    /// Numeric minimum (inclusive) for `int`/`float` bases, or item-count
    /// minimum for `list<string>`.
    pub min: Option<NumericBound>,
    /// Numeric maximum (inclusive) for `int`/`float` bases, or item-count
    /// maximum for `list<string>`.
    pub max: Option<NumericBound>,
    /// String format validator. Supported formats are `desktop-file-id`,
    /// `identifier`, `mime-type`, `srgb-color`, `shell-command`, and
    /// `target-path`.
    pub format: Option<String>,
    /// Documentation-only unit label (e.g. `"ms"`, `"px"`). Does not
    /// transform the coerced value.
    pub unit: Option<String>,
    /// Source span of the `refine` declaration.
    pub span: Span,
}

/// A refinement bound preserving authored integers exactly. Converting all
/// bounds to `f64` would collapse distinct i64 values above 2^53.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericBound {
    Int(i64),
    Float(f64),
}

impl NumericBound {
    pub(crate) fn compare(self, other: Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Int(left), Self::Int(right)) => left.cmp(&right),
            (Self::Int(left), Self::Float(right)) => compare_i64_f64(left, right),
            (Self::Float(left), Self::Int(right)) => compare_i64_f64(right, left).reverse(),
            (Self::Float(left), Self::Float(right)) => left
                .partial_cmp(&right)
                .expect("refinement bounds are finite"),
        }
    }

    fn compare_i64(self, value: i64) -> std::cmp::Ordering {
        match self {
            Self::Int(bound) => value.cmp(&bound),
            Self::Float(bound) => compare_i64_f64(value, bound),
        }
    }

    fn compare_f64(self, value: f64) -> std::cmp::Ordering {
        match self {
            Self::Int(bound) => compare_i64_f64(bound, value).reverse(),
            Self::Float(bound) => value
                .partial_cmp(&bound)
                .expect("refinement values and bounds are finite"),
        }
    }

    pub(crate) fn display(self) -> String {
        match self {
            Self::Int(value) => value.to_string(),
            Self::Float(value) => format_float(value),
        }
    }
}

impl RefineSchema {
    /// Validates a base-coerced value against this refinement's constraints.
    /// Returns `Ok(())` when the value is acceptable, or an error message
    /// describing the failure.
    pub fn validate(&self, value: &Value) -> Result<(), String> {
        match self.base.operational_type() {
            Type::Int => {
                let Some(i) = (match value {
                    Value::Int(i) => Some(*i),
                    _ => None,
                }) else {
                    return Err(format!("refine `{}` expected an int value", self.name));
                };
                if let Some(min) = self.min
                    && min.compare_i64(i).is_lt()
                {
                    return Err(format!(
                        "refine `{}` value `{}` is below the minimum of {}",
                        self.name,
                        value.display(),
                        min.display()
                    ));
                }
                if let Some(max) = self.max
                    && max.compare_i64(i).is_gt()
                {
                    return Err(format!(
                        "refine `{}` value `{}` is above the maximum of {}",
                        self.name,
                        value.display(),
                        max.display()
                    ));
                }
                Ok(())
            }
            Type::Float => {
                let Some(x) = (match value {
                    Value::Float(x) => Some(*x),
                    Value::Int(i) => exact_i64_to_f64(*i),
                    _ => None,
                }) else {
                    return Err(format!("refine `{}` expected a float value", self.name));
                };
                if let Some(min) = self.min
                    && min.compare_f64(x).is_lt()
                {
                    return Err(format!(
                        "refine `{}` value `{}` is below the minimum of {}",
                        self.name,
                        value.display(),
                        min.display()
                    ));
                }
                if let Some(max) = self.max
                    && max.compare_f64(x).is_gt()
                {
                    return Err(format!(
                        "refine `{}` value `{}` is above the maximum of {}",
                        self.name,
                        value.display(),
                        max.display()
                    ));
                }
                Ok(())
            }
            Type::String => {
                let Some(s) = (match value {
                    Value::String(s) | Value::Path(s) => Some(s.as_str()),
                    _ => None,
                }) else {
                    return Err(format!("refine `{}` expected a string value", self.name));
                };
                if let Some(format) = &self.format {
                    validate_string_format(format, s).map_err(|reason| {
                        format!(
                            "refine `{}` format `{format}` rejected `{s}`: {reason}",
                            self.name
                        )
                    })?;
                }
                Ok(())
            }
            Type::Path => Ok(()),
            Type::Bool => Ok(()),
            Type::List(item) => {
                let Some(items) = (match value {
                    Value::List(items) => Some(items),
                    _ => None,
                }) else {
                    return Err(format!("refine `{}` expected a list value", self.name));
                };
                let count = i64::try_from(items.len()).unwrap_or(i64::MAX);
                if let Some(min) = self.min
                    && min.compare_i64(count).is_lt()
                {
                    return Err(format!(
                        "refine `{}` has {} items, below the minimum of {}",
                        self.name,
                        items.len(),
                        min.display()
                    ));
                }
                if let Some(max) = self.max
                    && max.compare_i64(count).is_gt()
                {
                    return Err(format!(
                        "refine `{}` has {} items, above the maximum of {}",
                        self.name,
                        items.len(),
                        max.display()
                    ));
                }
                let _ = item;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Validates a string format. Returns `Ok(())` when the string matches the
/// format, or an error reason when it does not.
pub(crate) fn validate_string_format(format: &str, value: &str) -> Result<(), String> {
    match format {
        "desktop-file-id" => {
            let Some(stem) = value.strip_suffix(".desktop") else {
                return Err("desktop-file-id must end with `.desktop`".to_owned());
            };
            if stem.is_empty() {
                return Err(
                    "desktop-file-id must have a non-empty name before `.desktop`".to_owned(),
                );
            }
            if value.contains('/') {
                return Err("desktop-file-id must be an ID, not a path containing `/`".to_owned());
            }
            if value.chars().any(char::is_control) {
                return Err("desktop-file-id must not contain control characters".to_owned());
            }
            Ok(())
        }
        "identifier" => {
            if value.is_empty() {
                return Err("identifier must not be empty".to_owned());
            }
            let mut bytes = value.bytes();
            let first = bytes.next().expect("non-empty");
            if !first.is_ascii_lowercase() {
                return Err(format!(
                    "identifier must start with a lowercase ASCII letter (got `{}`)",
                    value.chars().next().unwrap_or(' ').escape_default()
                ));
            }
            for byte in bytes {
                if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-' {
                    return Err(format!(
                        "identifier must contain only lowercase letters, digits, or hyphens (got `{value}`)"
                    ));
                }
            }
            Ok(())
        }
        "mime-type" => {
            let Some((top_level, subtype)) = value.split_once('/') else {
                return Err("mime-type must contain exactly one `/` separator".to_owned());
            };
            if subtype.contains('/') {
                return Err("mime-type must contain exactly one `/` separator".to_owned());
            }
            for (part, name) in [("top-level type", top_level), ("subtype", subtype)] {
                if name.is_empty() || name.len() > 127 {
                    return Err(format!(
                        "mime-type {part} must contain between 1 and 127 ASCII characters"
                    ));
                }
                let mut bytes = name.bytes();
                let first = bytes.next().expect("non-empty MIME restricted name");
                if !first.is_ascii_alphanumeric() {
                    return Err(format!(
                        "mime-type {part} must start with an ASCII letter or digit"
                    ));
                }
                if !bytes.all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            byte,
                            b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
                        )
                }) {
                    return Err(format!(
                        "mime-type {part} contains a character outside the RFC 6838 restricted-name set"
                    ));
                }
            }
            Ok(())
        }
        "srgb-color" => {
            if value.len() != 7 && value.len() != 9 {
                return Err(format!(
                    "srgb-color must be `#rrggbb` or `#rrggbbaa` (got {len} characters)",
                    len = value.len()
                ));
            }
            let bytes = value.as_bytes();
            if bytes[0] != b'#' {
                return Err("srgb-color must start with `#`".to_owned());
            }
            for &byte in &bytes[1..] {
                if !byte.is_ascii_hexdigit() {
                    return Err(format!(
                        "srgb-color must contain only hex digits (got `{value}`)"
                    ));
                }
            }
            Ok(())
        }
        "shell-command" => {
            if value.is_empty() {
                return Err("shell-command must not be empty".to_owned());
            }
            Ok(())
        }
        "target-path" => {
            if value.is_empty() {
                return Err("target-path must not be empty".to_owned());
            }
            if value.starts_with('/') {
                return Err("target-path must be relative, not absolute".to_owned());
            }
            for segment in value.split('/') {
                if segment.is_empty() || segment == "." || segment == ".." {
                    return Err(format!(
                        "target-path must not contain empty segments, `.`, or `..` (got `{value}`)"
                    ));
                }
            }
            Ok(())
        }
        other => Err(format!("unknown format `{other}`")),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldSchema {
    pub name: String,
    pub ty: Type,
    pub required: bool,
    /// Raw field default. It is validated while named types and input schemas
    /// are resolved, then coerced again when a record omits the field.
    pub default: Option<Value>,
    pub default_span: Option<Span>,
    pub span: Span,
}

/// A tagged variant: a named discriminator field plus a closed set of cases.
#[derive(Debug, Clone, PartialEq)]
pub struct VariantSchema {
    /// The required string field that holds the active case name in the
    /// lowered record.
    pub discriminator: String,
    pub cases: Vec<VariantCase>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VariantCase {
    pub name: String,
    pub fields: Vec<FieldSchema>,
    pub span: Span,
}

impl FieldSchema {
    /// Returns the type seen by field lookup after record completion. Defaults
    /// and required fields are present; other fields remain optional.
    pub fn lookup_type(&self) -> Type {
        if self.default.is_some() || self.required || self.ty.is_optional() {
            self.ty.clone()
        } else {
            Type::Optional(Box::new(self.ty.clone()))
        }
    }
}

impl RecordSchema {
    pub fn field(&self, name: &str) -> Option<&FieldSchema> {
        self.fields.iter().find(|f| f.name == name)
    }
}

impl VariantSchema {
    pub fn case(&self, name: &str) -> Option<&VariantCase> {
        self.cases.iter().find(|case| case.name == name)
    }

    /// Returns the field schema exposed to record-path lookups. The
    /// discriminator is a synthetic required string. Case fields are optional
    /// because not every case declares them.
    pub fn field(&self, name: &str) -> Option<FieldSchema> {
        if name == self.discriminator {
            return Some(FieldSchema {
                name: name.to_owned(),
                ty: Type::String,
                required: true,
                default: None,
                default_span: None,
                span: Span::new(FileId(usize::MAX), 0, 0),
            });
        }
        for case in &self.cases {
            if let Some(field) = case.fields.iter().find(|f| f.name == name) {
                let mut field = field.clone();
                if !field.ty.is_optional() {
                    field.ty = Type::Optional(Box::new(field.ty));
                }
                field.required = false;
                return Some(field);
            }
        }
        None
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::Int => write!(f, "int"),
            Self::Float => write!(f, "float"),
            Self::String => write!(f, "string"),
            Self::Path => write!(f, "path"),
            Self::Enum(values) => write!(f, "enum{{{}}}", values.join(", ")),
            Self::List(item) => write!(f, "list<{item}>"),
            Self::Record(_) => write!(f, "record"),
            Self::Collection(item) => write!(f, "collection<{item}>"),
            Self::KdlDocument => write!(f, "kdl-document"),
            Self::Optional(inner) => write!(f, "optional<{inner}>"),
            Self::Named(name) => write!(f, "{name}"),
            Self::Variant(_) => write!(f, "variant"),
            Self::Refine(schema) => write!(f, "{}", schema.name),
            Self::Map(item) => write!(f, "map<{item}>"),
            Self::Tuple(types) => write!(
                f,
                "tuple<{}>",
                types
                    .iter()
                    .map(Type::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Set(item) => write!(f, "set<{item}>"),
        }
    }
}

impl Type {
    pub fn is_optional(&self) -> bool {
        matches!(self, Self::Optional(_))
    }

    /// Returns the type inside an `Optional`, or self.
    pub fn unwrap_optional(&self) -> &Type {
        match self {
            Self::Optional(inner) => inner,
            other => other,
        }
    }

    /// Returns the runtime shape represented by this type. Refinements retain
    /// schema constraints for coercion but otherwise behave like their base.
    pub fn operational_type(&self) -> &Type {
        let mut ty = self;
        while let Self::Refine(schema) = ty {
            ty = &schema.base;
        }
        ty
    }

    pub(crate) fn lowered_type(&self) -> LoweredType<'_> {
        match self.operational_type() {
            Self::Bool => LoweredType::Bool,
            Self::Int => LoweredType::Int,
            Self::Float => LoweredType::Float,
            Self::String => LoweredType::String,
            Self::Path => LoweredType::Path,
            Self::Enum(values) => LoweredType::Enum(values),
            Self::List(item) | Self::Set(item) => LoweredType::List(LoweredList::Homogeneous(item)),
            Self::Tuple(types) => LoweredType::List(LoweredList::Tuple(types)),
            Self::Record(_) | Self::Variant(_) => LoweredType::Record,
            Self::Collection(item) | Self::Map(item) => LoweredType::Collection(item),
            Self::KdlDocument => LoweredType::KdlDocument,
            Self::Optional(_) => LoweredType::Optional,
            Self::Named(_) => LoweredType::Named,
            Self::Refine(_) => unreachable!("operational_type removes refinements"),
        }
    }

    /// Returns whether `value` inhabits this type.
    ///
    /// `Null` is valid only for optionals.
    #[allow(dead_code)]
    pub fn accepts(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Optional(_), Value::Null) => true,
            (Self::Optional(inner), v) => inner.accepts(v),
            (_, Value::Null) => false,
            (Self::Bool, Value::Bool(_)) => true,
            (Self::Int, Value::Int(_)) => true,
            (Self::Float, Value::Float(_)) => true,
            (Self::Float, Value::Int(value)) => exact_i64_to_f64(*value).is_some(),
            (Self::String, Value::String(_)) => true,
            (Self::Path, Value::Path(_) | Value::String(_)) => true,
            (Self::Enum(values), Value::String(value)) => values.contains(value),
            (Self::List(item), Value::List(values)) => values.iter().all(|v| item.accepts(v)),
            (Self::Record(schema), Value::Record(record)) => {
                schema
                    .fields
                    .iter()
                    .all(|field| match record.get(&field.name) {
                        Some(Value::Null) => {
                            field.ty.is_optional() || (!field.required && field.default.is_none())
                        }
                        Some(v) => field.ty.accepts(v),
                        None => {
                            field.default.is_some() || !field.required || field.ty.is_optional()
                        }
                    })
                    && record.keys().all(|key| schema.field(key).is_some())
            }
            (Self::Collection(item), Value::Collection(collection)) => collection
                .items
                .iter()
                .all(|entry| item.accepts(&entry.value)),
            (Self::Map(item), Value::Collection(collection)) => collection
                .items
                .iter()
                .all(|entry| item.accepts(&entry.value)),
            (Self::Tuple(types), Value::List(values)) => {
                values.len() == types.len()
                    && values
                        .iter()
                        .zip(types.iter())
                        .all(|(value, ty)| ty.accepts(value))
            }
            (Self::Set(item), Value::List(values)) => {
                values.iter().all(|value| item.accepts(value))
            }
            (Self::KdlDocument, Value::KdlDocument(_)) => true,
            (Self::Named(_), _) => false,
            // Coercion lowers variants to records before this check.
            (Self::Variant(_), _) => false,
            (Self::Refine(schema), value) => {
                schema.base.accepts(value) && schema.validate(value).is_ok()
            }
            // Coercion lowers maps, sets, and tuples before this check.
            (Self::Map(_) | Self::Set(_) | Self::Tuple(_), _) => false,
            _ => false,
        }
    }
}

/// A finite `f64` ordered with `total_cmp` for use in [`Value::sort_key`].
#[derive(Clone, Copy, Debug)]
pub struct SortableFloat(f64);

impl SortableFloat {
    pub const fn new(value: f64) -> Self {
        Self(value)
    }
}

impl PartialEq for SortableFloat {
    fn eq(&self, other: &Self) -> bool {
        self.0.total_cmp(&other.0) == std::cmp::Ordering::Equal
    }
}

impl Eq for SortableFloat {}

impl PartialOrd for SortableFloat {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SortableFloat {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

/// Comparable representation of a scalar [`Value`] used to canonicalize the
/// order of `set<T>` elements after deduplication.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ValueSortKey {
    Null,
    /// `false` sorts before `true`.
    Bool(bool),
    /// Numeric ordering by signed value.
    Int(i64),
    /// Numeric ordering via `f64::total_cmp`.
    Float(SortableFloat),
    /// Lexicographic string ordering.
    String(String),
    /// Lexicographic path ordering. Distinct from [`Self::String`] so mixed
    /// sets keep strings before paths.
    Path(String),
}

/// One item of a keyed collection: a stable key plus its payload.
#[derive(Debug, Clone, PartialEq)]
pub struct CollectionItem {
    pub key: String,
    pub value: Value,
    /// Where this item was declared (default or patch site).
    pub span: Span,
}

/// An ordered, keyed collection. Keys are unique; iteration follows
/// declaration order (defaults first, then appended patches).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeyedCollection {
    pub items: Vec<CollectionItem>,
}

impl KeyedCollection {
    pub fn get(&self, key: &str) -> Option<&CollectionItem> {
        self.items.iter().find(|item| item.key == key)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// A record-shaped literal before its named schema is known. Properties stay
/// ordered and spanned so coercion can validate them together with child-form
/// fields without losing cross-form duplicate locations.
#[derive(Debug, Clone, PartialEq)]
pub struct RawRecordLiteral {
    pub properties: Vec<RawRecordProperty>,
    pub children: KdlDocument,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RawRecordProperty {
    pub name: String,
    pub value: Value,
    pub span: Span,
}

/// A record value: closed set of named fields.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Record {
    fields: BTreeMap<String, Value>,
}

impl Record {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: String, value: Value) -> Option<Value> {
        self.fields.insert(name, value)
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.get(name)
    }

    /// Returns a mutable reference to a single field.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Value> {
        self.fields.get_mut(name)
    }

    /// Resolves a dotted field path recursively. An exact field name takes
    /// precedence, so field names containing dots remain addressable.
    pub fn get_path(&self, path: &str) -> Option<&Value> {
        if let Some(value) = self.get(path) {
            return Some(value);
        }
        let (head, tail) = path.split_once('.')?;
        self.get(head)?.get_path(tail)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.fields.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.fields.iter()
    }
}

/// A typed value. `Null` exists only as the state of an unset/cleared
/// optional. It never inhabits a non-optional type.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    /// A lexically normalized path. A `~/` prefix remains symbolic.
    Path(String),
    List(Vec<Value>),
    Record(Record),
    Collection(KeyedCollection),
    KdlDocument(KdlDocument),
    /// Parse-only record/variant literal. Successful coercion always replaces
    /// this with a completed [`Value::Record`].
    RawRecordLiteral(RawRecordLiteral),
    /// Parse-only marker for `list<Named>`'s singular record or empty-list
    /// default. Named type resolution disambiguates and removes it.
    UnresolvedListDefault(RawRecordLiteral),
}

impl Value {
    /// Compares values after coercion. Source spans on collection items do
    /// not affect values, and paths compare by their canonical text to string
    /// literals used by predicates.
    pub fn semantic_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Int(left), Self::Int(right)) => left == right,
            (Self::Float(left), Self::Float(right)) => left == right,
            (Self::String(left) | Self::Path(left), Self::String(right) | Self::Path(right)) => {
                left == right
            }
            (Self::List(left), Self::List(right)) => {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right)
                        .all(|(left, right)| left.semantic_eq(right))
            }
            (Self::Record(left), Self::Record(right)) => {
                left.fields.len() == right.fields.len()
                    && left.fields.iter().all(|(name, left)| {
                        right
                            .fields
                            .get(name)
                            .is_some_and(|right| left.semantic_eq(right))
                    })
            }
            (Self::Collection(left), Self::Collection(right)) => {
                left.items.len() == right.items.len()
                    && left.items.iter().zip(&right.items).all(|(left, right)| {
                        left.key == right.key && left.value.semantic_eq(&right.value)
                    })
            }
            (Self::KdlDocument(left), Self::KdlDocument(right)) => left == right,
            (Self::RawRecordLiteral(left), Self::RawRecordLiteral(right)) => left == right,
            (Self::UnresolvedListDefault(left), Self::UnresolvedListDefault(right)) => {
                left == right
            }
            _ => false,
        }
    }

    /// Resolves a path below this value. Null propagates through further field
    /// access, matching optional-record lookup semantics.
    pub fn get_path(&self, path: &str) -> Option<&Value> {
        if path.is_empty() {
            return Some(self);
        }
        match self {
            Self::Record(record) => record.get_path(path),
            Self::Collection(collection) => {
                if let Some(item) = collection.get(path) {
                    return Some(&item.value);
                }
                if let Some((key, tail)) = path.split_once('.')
                    && let Some(item) = collection.get(key)
                {
                    return item.value.get_path(tail).or(Some(&NULL_VALUE));
                }
                Some(&NULL_VALUE)
            }
            Self::List(values) => {
                if let Ok(index) = path.parse::<usize>() {
                    return values.get(index).or(Some(&NULL_VALUE));
                }
                let (index, tail) = path.split_once('.')?;
                values
                    .get(index.parse::<usize>().ok()?)
                    .and_then(|value| value.get_path(tail))
                    .or(Some(&NULL_VALUE))
            }
            Self::Null => Some(self),
            _ => None,
        }
    }

    /// Returns the intrinsic type label used in diagnostics.
    pub fn type_label(&self) -> String {
        match self {
            Self::Null => "null".to_owned(),
            Self::Bool(_) => "bool".to_owned(),
            Self::Int(_) => "int".to_owned(),
            Self::Float(_) => "float".to_owned(),
            Self::String(_) => "string".to_owned(),
            Self::Path(_) => "path".to_owned(),
            Self::List(_) => "list".to_owned(),
            Self::Record(_) => "record".to_owned(),
            Self::Collection(_) => "collection".to_owned(),
            Self::KdlDocument(_) => "kdl-document".to_owned(),
            Self::RawRecordLiteral(_) => "raw-record-literal".to_owned(),
            Self::UnresolvedListDefault(_) => "unresolved-list-default".to_owned(),
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns a comparable key for a set scalar. Set declarations reject
    /// aggregate element types before coercion, so every accepted value has an
    /// injective structural key.
    pub fn sort_key(&self) -> ValueSortKey {
        match self {
            Self::Null => ValueSortKey::Null,
            Self::Bool(b) => ValueSortKey::Bool(*b),
            Self::Int(i) => ValueSortKey::Int(*i),
            Self::Float(x) => ValueSortKey::Float(SortableFloat::new(*x)),
            Self::String(s) => ValueSortKey::String(s.clone()),
            Self::Path(s) => ValueSortKey::Path(s.clone()),
            _ => unreachable!("aggregate set elements are rejected during type resolution"),
        }
    }

    /// Formats a value for `malm vars` and diagnostics. Artifact serialization
    /// always uses codecs instead.
    pub fn display(&self) -> String {
        match self {
            Self::Null => "#null".to_owned(),
            Self::Bool(b) => format!("#{b}"),
            Self::Int(i) => i.to_string(),
            Self::Float(x) => format_float(*x),
            Self::String(s) => s.clone(),
            Self::Path(p) => p.clone(),
            Self::List(items) => {
                let rendered: Vec<String> = items.iter().map(Value::display).collect();
                format!("[{}]", rendered.join(", "))
            }
            Self::Record(record) => {
                let rendered: Vec<String> = record
                    .iter()
                    .map(|(k, v)| format!("{k}={}", v.display()))
                    .collect();
                format!("{{{}}}", rendered.join(", "))
            }
            Self::Collection(collection) => {
                let keys: Vec<&str> = collection.items.iter().map(|i| i.key.as_str()).collect();
                format!("collection[{}]", keys.join(", "))
            }
            Self::KdlDocument(_) => "kdl-document".to_owned(),
            Self::RawRecordLiteral(_) => "raw-record-literal".to_owned(),
            Self::UnresolvedListDefault(_) => "unresolved-list-default".to_owned(),
        }
    }
}

static NULL_VALUE: Value = Value::Null;

/// Formats a float the way KDL renders it, keeping `1.0` distinguishable
/// from the int `1`.
pub fn format_float(x: f64) -> String {
    if x.fract() == 0.0 && x.is_finite() && x.abs() < 1e15 {
        format!("{x:.1}")
    } else {
        format!("{x}")
    }
}

/// Converts an integer only when its value is represented exactly by `f64`.
pub fn exact_i64_to_f64(value: i64) -> Option<f64> {
    let converted = value as f64;
    ((converted as i128) == i128::from(value)).then_some(converted)
}

/// Compares an `i64` with a finite `f64` without first rounding the integer.
fn compare_i64_f64(integer: i64, float: f64) -> std::cmp::Ordering {
    debug_assert!(float.is_finite());
    const I64_UPPER_EXCLUSIVE: f64 = 9_223_372_036_854_775_808.0;
    const I64_LOWER_INCLUSIVE: f64 = -9_223_372_036_854_775_808.0;

    if float >= I64_UPPER_EXCLUSIVE {
        return std::cmp::Ordering::Less;
    }
    if float < I64_LOWER_INCLUSIVE {
        return std::cmp::Ordering::Greater;
    }

    let truncated = float.trunc() as i64;
    match integer.cmp(&truncated) {
        std::cmp::Ordering::Equal if float > truncated as f64 => std::cmp::Ordering::Less,
        std::cmp::Ordering::Equal if float < truncated as f64 => std::cmp::Ordering::Greater,
        ordering => ordering,
    }
}

#[cfg(test)]
mod tests {
    use super::exact_i64_to_f64;

    #[test]
    fn integer_to_float_requires_exact_representation() {
        assert_eq!(
            exact_i64_to_f64(9_007_199_254_740_992),
            Some(9_007_199_254_740_992.0)
        );
        assert_eq!(exact_i64_to_f64(9_007_199_254_740_993), None);
        assert_eq!(exact_i64_to_f64(i64::MAX), None);
        assert_eq!(exact_i64_to_f64(i64::MIN), Some(i64::MIN as f64));
    }
}

/// Which layer produced a resolved value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ValueOrigin {
    /// A module input's declared default.
    Default,
    /// Set by profile `with`.
    Profile(String),
    /// A built-in such as `malm.target` or `instance.name`.
    Builtin,
    /// A `global.*` variable from config or a machine include.
    Global,
    /// A loop binding introduced by `@for-each` / `@for-range`.
    Binding,
}

impl ValueOrigin {
    /// Returns the stable label used in variable provenance reports.
    #[allow(dead_code)]
    pub fn label(&self) -> String {
        match self {
            Self::Default => "default".to_owned(),
            Self::Profile(name) => format!("profile {name}"),
            Self::Builtin => "built-in".to_owned(),
            Self::Global => "global".to_owned(),
            Self::Binding => "loop binding".to_owned(),
        }
    }
}
