//! Typed values retained until artifact serialization.

use crate::lang::diag::Span;
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
    /// Keyed collection; the payload type of every item.
    Collection(Box<Type>),
    KdlDocument,
    Optional(Box<Type>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordSchema {
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldSchema {
    pub name: String,
    pub ty: Type,
    pub required: bool,
    pub span: Span,
}

impl RecordSchema {
    pub fn field(&self, name: &str) -> Option<&FieldSchema> {
        self.fields.iter().find(|f| f.name == name)
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
        }
    }
}

impl Type {
    pub fn is_optional(&self) -> bool {
        matches!(self, Self::Optional(_))
    }

    /// The type inside an `Optional`, or self.
    pub fn unwrap_optional(&self) -> &Type {
        match self {
            Self::Optional(inner) => inner,
            other => other,
        }
    }

    /// Whether `value` inhabits this type. `Null` is valid only for optionals.
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
                        Some(Value::Null) => !field.required,
                        Some(v) => field.ty.accepts(v),
                        None => !field.required,
                    })
                    && record.keys().all(|key| schema.field(key).is_some())
            }
            (Self::Collection(item), Value::Collection(collection)) => collection
                .items
                .iter()
                .all(|entry| item.accepts(&entry.value)),
            (Self::KdlDocument, Value::KdlDocument(_)) => true,
            _ => false,
        }
    }
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
    /// An absolute, tilde-expanded filesystem path.
    Path(String),
    List(Vec<Value>),
    Record(Record),
    Collection(KeyedCollection),
    KdlDocument(KdlDocument),
}

impl Value {
    /// The intrinsic type label of this value, for diagnostics.
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
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Human-readable display for `malm vars` and diagnostics. Never used
    /// to serialize into artifacts (codecs do that).
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
        }
    }
}

/// Format a float the way KDL renders it, keeping `1.0` distinguishable
/// from the int `1`.
pub fn format_float(x: f64) -> String {
    if x.fract() == 0.0 && x.is_finite() && x.abs() < 1e15 {
        format!("{x:.1}")
    } else {
        format!("{x}")
    }
}

/// Convert an integer only when its value is represented exactly by `f64`.
pub fn exact_i64_to_f64(value: i64) -> Option<f64> {
    let converted = value as f64;
    ((converted as i128) == i128::from(value)).then_some(converted)
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
    /// A built-in (`malm.target`, `instance.name`, …).
    Builtin,
    /// A `global.*` variable from config or a machine include.
    Global,
    /// A loop binding introduced by `each` / `range`.
    Binding,
}

impl ValueOrigin {
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
