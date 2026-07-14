//! Substitution-only templates and codecs. Templates accept `{{path}}` and
//! `{{path:codec}}`; control flow and includes belong in KDL outputs.
//!
//! Codecs are explicit: `text`, `int`, `float`, `bool`, `toml-string`,
//! `toml-array`, `json`, `shell-word`, `raw`, plus `literal "…"` as the escape
//! hatch for emitting literal braces.

use crate::lang::value::{Type, Value, exact_i64_to_f64, format_float};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Text,
    Int,
    Float,
    Bool,
    TomlString,
    TomlArray,
    Json,
    ShellWord,
    Lua,
    Raw,
    /// The implicit codec for `{{path}}`, selected from the value type.
    Auto,
}

impl Codec {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "text" => Self::Text,
            "int" => Self::Int,
            "float" => Self::Float,
            "bool" => Self::Bool,
            "toml-string" => Self::TomlString,
            "toml-array" => Self::TomlArray,
            "json" => Self::Json,
            "shell-word" | "shell" => Self::ShellWord,
            "lua" => Self::Lua,
            "raw" => Self::Raw,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::TomlString => "toml-string",
            Self::TomlArray => "toml-array",
            Self::Json => "json",
            Self::ShellWord => "shell-word",
            Self::Lua => "lua",
            Self::Raw => "raw",
            Self::Auto => "auto",
        }
    }

    /// Whether this codec accepts `ty`.
    /// Optionals are rejected until flow refinement proves a `when-set` guard.
    pub fn accepts_type(self, ty: &Type) -> bool {
        if ty.is_optional() {
            return false;
        }
        let inner = ty;
        match self {
            Self::Text => matches!(inner, Type::String | Type::Path | Type::Enum(_)),
            Self::Int => matches!(inner, Type::Int),
            Self::Float => matches!(inner, Type::Float | Type::Int),
            Self::Bool => matches!(inner, Type::Bool),
            Self::TomlArray => {
                matches!(inner, Type::List(item) if is_toml_scalar_type(item))
            }
            Self::TomlString
            | Self::Json
            | Self::ShellWord
            | Self::Lua
            | Self::Raw
            | Self::Auto => matches!(
                inner,
                Type::String | Type::Path | Type::Enum(_) | Type::Int | Type::Float | Type::Bool
            ),
        }
    }

    /// Encode a typed value with this codec.
    pub fn encode(self, value: &Value) -> Result<String, String> {
        if value.is_null() {
            return Err("value is #null; guard the reference with `when-set`".to_owned());
        }
        match self {
            Self::Text => match value {
                Value::String(s) => Ok(s.clone()),
                Value::Path(p) => Ok(p.clone()),
                other => Err(format!(
                    "`text` requires a string, found {}",
                    other.type_label()
                )),
            },
            Self::Int => match value {
                Value::Int(i) => Ok(i.to_string()),
                other => Err(format!(
                    "`int` requires an int, found {}",
                    other.type_label()
                )),
            },
            Self::Float => match value {
                Value::Float(x) => Ok(format_float(*x)),
                Value::Int(i) => exact_i64_to_f64(*i).map(format_float).ok_or_else(|| {
                    format!("integer `{i}` cannot be represented exactly as a float")
                }),
                other => Err(format!(
                    "`float` requires a float, found {}",
                    other.type_label()
                )),
            },
            Self::Bool => match value {
                Value::Bool(b) => Ok(b.to_string()),
                other => Err(format!(
                    "`bool` requires a bool, found {}",
                    other.type_label()
                )),
            },
            Self::TomlString => scalar_text(value, self).map(|s| toml_string(&s)),
            Self::TomlArray => match value {
                Value::List(items) => {
                    let encoded = items
                        .iter()
                        .map(toml_scalar)
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(format!("[{}]", encoded.join(", ")))
                }
                other => Err(format!(
                    "`toml-array` requires a list, found {}",
                    other.type_label()
                )),
            },
            Self::Json => match value {
                Value::String(s) | Value::Path(s) => {
                    Ok(serde_json::to_string(s).unwrap_or_default())
                }
                Value::Int(i) => Ok(i.to_string()),
                Value::Float(x) => Ok(serde_json::to_string(x).unwrap_or_default()),
                Value::Bool(b) => Ok(b.to_string()),
                other => Err(format!(
                    "`json` requires a scalar, found {}",
                    other.type_label()
                )),
            },
            Self::ShellWord => scalar_text(value, self).map(|s| shell_word(&s)),
            Self::Lua => match value {
                Value::String(s) | Value::Path(s) => Ok(format!(
                    "\"{}\"",
                    crate::lang::config_file::generic::lua_escape(s)
                )),
                Value::Int(i) => Ok(i.to_string()),
                Value::Float(x) => Ok(format_float(*x)),
                Value::Bool(b) => Ok(b.to_string()),
                other => Err(format!(
                    "`lua` requires a scalar, found {}",
                    other.type_label()
                )),
            },
            Self::Raw | Self::Auto => scalar_text(value, self),
        }
    }
}

fn is_toml_scalar_type(ty: &Type) -> bool {
    matches!(
        ty,
        Type::String | Type::Path | Type::Enum(_) | Type::Int | Type::Float | Type::Bool
    )
}

fn toml_scalar(value: &Value) -> Result<String, String> {
    match value {
        Value::String(s) | Value::Path(s) => Ok(toml_string(s)),
        Value::Int(i) => Ok(i.to_string()),
        Value::Float(x) => Ok(format_float(*x)),
        Value::Bool(b) => Ok(b.to_string()),
        other => Err(format!(
            "`toml-array` requires TOML scalar items, found {}",
            other.type_label()
        )),
    }
}

fn scalar_text(value: &Value, codec: Codec) -> Result<String, String> {
    match value {
        Value::String(s) | Value::Path(s) => Ok(s.clone()),
        Value::Int(i) => Ok(i.to_string()),
        Value::Float(x) => Ok(format_float(*x)),
        Value::Bool(b) => Ok(b.to_string()),
        other => Err(format!(
            "`{}` requires a scalar, found {}",
            codec.label(),
            other.type_label()
        )),
    }
}

/// TOML basic-string encoding (quotes + escapes).
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{007F}' => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Quote a string as one POSIX shell word (single-quote strategy).
pub(crate) fn shell_word(s: &str) -> String {
    if !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '=' | '+' | ',')
        })
    {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// A parsed template directive.
#[derive(Debug, PartialEq)]
pub enum Directive<'a> {
    /// `{{path}}` or `{{path:codec}}`.
    Substitute { codec: Codec, name: &'a str },
    /// `{{literal "…"}}` emits the quoted text verbatim.
    Literal(String),
}

/// A parsed template: alternating literal text and directives.
#[derive(Debug)]
pub enum Segment<'a> {
    Text(&'a str),
    Directive { raw: &'a str, parsed: Directive<'a> },
}

/// Placeholder syntax accepted by the template engine. V3 accepts `{{path}}`
/// and `{{path:codec}}`, and rejects the legacy `{{codec name}}` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateSyntax {
    V3,
}

/// Parse a substitution-only template, rejecting malformed directives and
/// control-flow syntax.
pub fn parse_template_with(
    input: &str,
    syntax: TemplateSyntax,
) -> Result<Vec<Segment<'_>>, String> {
    let mut segments = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        match rest.find("{{") {
            None => {
                segments.push(Segment::Text(rest));
                break;
            }
            Some(open) => {
                if open > 0 {
                    segments.push(Segment::Text(&rest[..open]));
                }
                let after = &rest[open + 2..];
                // Find the closing `}}` outside double quotes, so
                // `{{literal "{{token}}"}}` can carry braces in its payload.
                let Some(close) = find_directive_close(after) else {
                    return Err("unterminated `{{` directive".to_owned());
                };
                let raw = &after[..close];
                segments.push(Segment::Directive {
                    raw,
                    parsed: parse_directive(raw, syntax)?,
                });
                rest = &after[close + 2..];
            }
        }
    }
    Ok(segments)
}

fn find_directive_close(after: &str) -> Option<usize> {
    let bytes = after.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            _ if escaped => escaped = false,
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'}' if !in_string && index + 1 < bytes.len() && bytes[index + 1] == b'}' => {
                return Some(index);
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn parse_directive(raw: &str, syntax: TemplateSyntax) -> Result<Directive<'_>, String> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("literal")
        && rest.starts_with(char::is_whitespace)
    {
        let rest = rest.trim();
        let inner: String = serde_json::from_str(rest).map_err(|_| {
            "`literal` expects one escape-aware double-quoted string: {{literal \"…\"}}".to_owned()
        })?;
        return Ok(Directive::Literal(inner));
    }
    if trimmed.starts_with('#') || trimmed.starts_with('/') || trimmed.starts_with("include") {
        return Err(format!(
            "`{{{{{raw}}}}}`: templates are substitution-only — control flow and includes live in KDL outputs (when / each / range / emit-file)"
        ));
    }
    let mut parts = trimmed.split_whitespace();
    match (parts.next(), parts.next(), syntax) {
        // `{{path}}` or `{{path:codec}}`.
        (Some(token), None, TemplateSyntax::V3) => match token.split_once(':') {
            None => Ok(Directive::Substitute {
                codec: Codec::Auto,
                name: token,
            }),
            Some((name, codec_name)) => {
                if name.is_empty() {
                    return Err(format!("malformed directive `{{{{{raw}}}}}`: empty path"));
                }
                let codec = Codec::parse(codec_name).ok_or_else(|| unknown_codec(codec_name))?;
                Ok(Directive::Substitute { codec, name })
            }
        },
        (_, _, TemplateSyntax::V3) => Err(format!(
            "malformed directive `{{{{{raw}}}}}`; use `{{{{path}}}}` or `{{{{path:codec}}}}` (control flow lives in KDL outputs)"
        )),
    }
}

fn unknown_codec(name: &str) -> String {
    format!(
        "unknown codec `{name}` (known: text, int, float, bool, toml-string, toml-array, json, shell-word, shell, lua, raw, literal)"
    )
}

/// Statically check a template against a type environment. Returns
/// human-readable issues (empty = clean).
pub fn check_template_with_v3(input: &str, lookup: &dyn Fn(&str) -> Option<Type>) -> Vec<String> {
    check_template_with(input, TemplateSyntax::V3, lookup)
}

/// [`check_template`] with an explicit placeholder syntax.
pub fn check_template_with(
    input: &str,
    syntax: TemplateSyntax,
    lookup: &dyn Fn(&str) -> Option<Type>,
) -> Vec<String> {
    let segments = match parse_template_with(input, syntax) {
        Ok(segments) => segments,
        Err(message) => return vec![message],
    };
    let mut issues = Vec::new();
    for segment in segments {
        if let Segment::Directive {
            parsed: Directive::Substitute { codec, name },
            ..
        } = segment
        {
            match lookup(name) {
                None => issues.push(format!("`{name}` is not defined in this module's scope")),
                Some(ty) => {
                    if !codec.accepts_type(&ty) {
                        issues.push(format!(
                            "`{{{{{} {name}}}}}`: codec `{}` does not accept {ty}",
                            codec.label(),
                            codec.label()
                        ));
                    }
                }
            }
        }
    }
    issues
}

/// Render a template against a runtime scope.
pub fn render_template_with_v3(
    input: &str,
    lookup: &dyn Fn(&str) -> Option<Value>,
) -> Result<String, String> {
    render_template_with(input, TemplateSyntax::V3, lookup)
}

/// [`render_template`] with an explicit placeholder syntax.
pub fn render_template_with(
    input: &str,
    syntax: TemplateSyntax,
    lookup: &dyn Fn(&str) -> Option<Value>,
) -> Result<String, String> {
    let segments = parse_template_with(input, syntax)?;
    let mut out = String::with_capacity(input.len());
    for segment in segments {
        match segment {
            Segment::Text(text) => out.push_str(text),
            Segment::Directive { parsed, raw } => match parsed {
                Directive::Literal(text) => out.push_str(&text),
                Directive::Substitute { codec, name } => {
                    let value = lookup(name)
                        .ok_or_else(|| format!("`{name}` is not defined (in `{{{{{raw}}}}}`)"))?;
                    let encoded = codec
                        .encode(&value)
                        .map_err(|m| format!("{m} (in `{{{{{raw}}}}}`)"))?;
                    out.push_str(&encoded);
                }
            },
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders_substitutions() {
        let lookup = |name: &str| -> Option<Value> {
            match name {
                "tag" => Some(Value::Int(4)),
                "name" => Some(Value::String("a b".to_owned())),
                _ => None,
            }
        };
        let rendered = render_template_with_v3(
            "id:{{tag:int}} n={{name:shell-word}} {{literal \"{{\"}}ok",
            &lookup,
        )
        .unwrap();
        assert_eq!(rendered, "id:4 n='a b' {{ok");
    }

    #[test]
    fn rejects_control_flow() {
        assert!(parse_template_with("{{#if x}}", TemplateSyntax::V3).is_err());
        assert!(parse_template_with("{{ include \"x\" }}", TemplateSyntax::V3).is_err());
        // V3 accepts bare paths and path:codec, but rejects codec-name order.
        assert!(parse_template_with("{{bare}}", TemplateSyntax::V3).is_ok());
        assert!(parse_template_with("{{name:shell}}", TemplateSyntax::V3).is_ok());
        assert!(parse_template_with("{{int name}}", TemplateSyntax::V3).is_err());
    }

    #[test]
    fn null_needs_guard() {
        let lookup = |_: &str| Some(Value::Null);
        let err = render_template_with_v3("{{x:int}}", &lookup).unwrap_err();
        assert!(err.contains("when-set"), "{err}");
    }

    #[test]
    fn toml_and_json_escape() {
        let lookup = |_: &str| Some(Value::String("a\"b\\c".to_owned()));
        assert_eq!(
            render_template_with_v3("{{x:toml-string}}", &lookup).unwrap(),
            "\"a\\\"b\\\\c\""
        );
        assert_eq!(
            render_template_with_v3("{{x:json}}", &lookup).unwrap(),
            "\"a\\\"b\\\\c\""
        );
    }

    #[test]
    fn toml_string_escapes_disallowed_control_characters() {
        assert_eq!(toml_string("\u{0001}\u{007F}"), "\"\\u0001\\u007F\"");
    }

    #[test]
    fn toml_array_encodes_scalar_lists() {
        let lookup = |name: &str| match name {
            "strings" => Some(Value::List(vec![
                Value::String("a\"b".to_owned()),
                Value::Path("/tmp/a b".to_owned()),
            ])),
            "ints" => Some(Value::List(vec![Value::Int(1), Value::Int(-2)])),
            "floats" => Some(Value::List(vec![Value::Float(1.5), Value::Float(2.0)])),
            "bools" => Some(Value::List(vec![Value::Bool(true), Value::Bool(false)])),
            "empty" => Some(Value::List(Vec::new())),
            _ => None,
        };

        assert_eq!(
            render_template_with_v3("{{strings:toml-array}}", &lookup).unwrap(),
            "[\"a\\\"b\", \"/tmp/a b\"]"
        );
        assert_eq!(
            render_template_with_v3("{{ints:toml-array}}", &lookup).unwrap(),
            "[1, -2]"
        );
        assert_eq!(
            render_template_with_v3("{{floats:toml-array}}", &lookup).unwrap(),
            "[1.5, 2.0]"
        );
        assert_eq!(
            render_template_with_v3("{{bools:toml-array}}", &lookup).unwrap(),
            "[true, false]"
        );
        assert_eq!(
            render_template_with_v3("{{empty:toml-array}}", &lookup).unwrap(),
            "[]"
        );
    }

    #[test]
    fn toml_array_rejects_non_lists_and_non_scalar_items() {
        let issues = check_template_with_v3("{{value:toml-array}}", &|_| Some(Type::String));
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].contains("does not accept string"),
            "{}",
            issues[0]
        );

        let error = render_template_with_v3("{{value:toml-array}}", &|_| {
            Some(Value::List(vec![Value::List(Vec::new())]))
        })
        .unwrap_err();
        assert!(
            error.contains("requires TOML scalar items, found list"),
            "{error}"
        );
    }

    #[test]
    fn literal_scanner_honors_escaped_quotes_and_braces() {
        let rendered =
            render_template_with_v3(r#"{{literal "a \"quoted\" }} value"}}"#, &|_| None).unwrap();
        assert_eq!(rendered, "a \"quoted\" }} value");
    }
}
