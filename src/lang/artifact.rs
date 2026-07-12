//! In-memory generated artifacts and target-format validation.

use crate::lang::ast::KdlDialect;
use crate::lang::diag::Span;

/// An in-memory generated file.
#[derive(Debug)]
pub struct Artifact {
    /// Destination as written in the config (`to=`), target-root relative
    /// or `~/`-absolute.
    pub to: String,
    pub content: String,
    pub executable: bool,
    /// Format validators in execution order. Generic config files put their
    /// intrinsic codec first and an optional user validator second.
    pub validators: Vec<String>,
    pub instance: String,
    pub module: String,
    pub span: Span,
}

pub(crate) const KNOWN_VALIDATORS: &[&str] = &[
    "text",
    "json",
    "jsonc",
    "toml",
    "xml",
    "ini",
    "kdl-v1",
    "kdl-v2",
    "hypr",
    "hyprlock",
    "hypridle",
    "lua",
    "css",
    "gtk-css",
    "key-value",
    "line-list",
    "scalar",
    "mango",
    "kanshi",
    "shell",
];

pub(crate) fn validator_known(name: &str) -> bool {
    KNOWN_VALIDATORS.contains(&name)
}

pub(crate) fn known_validators_help() -> String {
    format!("known validators: {}", KNOWN_VALIDATORS.join(", "))
}

/// Validate `content` against a named format. An empty result is valid.
pub fn validate_format(name: &str, content: &str) -> Vec<String> {
    match name {
        "text" => Vec::new(),
        "json" => match serde_json::from_str::<serde_json::Value>(content) {
            Ok(_) => Vec::new(),
            Err(error) => vec![format!("invalid JSON: {error}")],
        },
        "jsonc" => {
            let stripped = match strip_json_comments(content) {
                Ok(stripped) => stripped,
                Err(problem) => return vec![format!("invalid JSONC: {problem}")],
            };
            match serde_json::from_str::<serde_json::Value>(&stripped) {
                Ok(_) => Vec::new(),
                Err(error) => vec![format!("invalid JSONC: {error}")],
            }
        }
        "toml" => match toml::from_str::<toml::Value>(content) {
            Ok(_) => Vec::new(),
            Err(error) => vec![format!("invalid TOML: {error}")],
        },
        "xml" => match roxmltree::Document::parse(content) {
            Ok(_) => Vec::new(),
            Err(error) => vec![format!("invalid XML: {error}")],
        },
        "ini" => validate_ini(content),
        "kdl-v1" => validate_kdl(content, KdlDialect::V1),
        "kdl-v2" => validate_kdl(content, KdlDialect::V2),
        // Hypr-style and mango conf: comments, blank lines, `key = value` /
        // `key=value` assignments, and `section {` … `}` blocks.
        "hypr" | "hyprlock" | "hypridle" => validate_conf_lines(content),
        "mango" => validate_mango(content),
        "kanshi" => validate_kanshi(content),
        "lua" => validate_lua(content),
        "css" => validate_css(content),
        "gtk-css" => validate_gtk_css(content),
        "key-value" | "line-list" => validate_safe_lines(content),
        "scalar" => validate_scalar(content),
        "shell" => validate_shell(content),
        other => vec![format!("unknown validator `{other}`")],
    }
}

fn validate_shell(content: &str) -> Vec<String> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_bash::LANGUAGE.into();
    if let Err(error) = parser.set_language(&language) {
        return vec![format!("shell validator initialization failed: {error}")];
    }
    let Some(tree) = parser.parse(content, None) else {
        return vec!["shell parser did not produce a syntax tree".to_owned()];
    };
    if !tree.root_node().has_error() {
        return Vec::new();
    }

    let mut problems = Vec::new();
    collect_shell_errors(tree.root_node(), content, &mut problems);
    if problems.is_empty() {
        problems.push("invalid shell syntax".to_owned());
    }
    problems
}

fn validate_lua(content: &str) -> Vec<String> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_lua::LANGUAGE.into();
    if let Err(error) = parser.set_language(&language) {
        return vec![format!("Lua validator initialization failed: {error}")];
    }
    let Some(tree) = parser.parse(content, None) else {
        return vec!["Lua parser did not produce a syntax tree".to_owned()];
    };
    if !tree.root_node().has_error() {
        return Vec::new();
    }
    let mut problems = Vec::new();
    collect_lua_errors(tree.root_node(), content, &mut problems);
    if problems.is_empty() {
        problems.push("invalid Lua syntax".to_owned());
    }
    problems
}

fn validate_css(content: &str) -> Vec<String> {
    validate_css_source("CSS", content, content)
}

fn validate_gtk_css(content: &str) -> Vec<String> {
    let masked = match mask_gtk_css(content) {
        Ok(masked) => masked,
        Err(problem) => return vec![format!("invalid GTK CSS: {problem}")],
    };
    validate_css_source("GTK CSS", content, &masked)
}

fn validate_css_source(label: &str, original: &str, parsed: &str) -> Vec<String> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_css::LANGUAGE.into();
    if let Err(error) = parser.set_language(&language) {
        return vec![format!("{label} validator initialization failed: {error}")];
    }
    let Some(tree) = parser.parse(parsed, None) else {
        return vec![format!("{label} parser did not produce a syntax tree")];
    };
    if !tree.root_node().has_error() {
        return Vec::new();
    }
    let mut problems = Vec::new();
    collect_css_errors(tree.root_node(), original, label, &mut problems);
    if problems.is_empty() {
        problems.push(format!("invalid {label} syntax"));
    }
    problems
}

fn mask_gtk_css(content: &str) -> Result<String, String> {
    for (offset, character) in content.char_indices() {
        if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
            let line = content[..offset]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1;
            return Err(format!("unsafe control character on line {line}"));
        }
    }

    #[derive(Clone, Copy)]
    enum State {
        Normal,
        SingleQuoted,
        DoubleQuoted,
        Comment,
    }

    let mut bytes = content.as_bytes().to_vec();
    let mut state = State::Normal;
    let mut statement_start = true;
    let mut index = 0;
    while index < bytes.len() {
        match state {
            State::Normal if bytes[index..].starts_with(b"/*") => {
                state = State::Comment;
                index += 2;
            }
            State::Normal if bytes[index] == b'\'' => {
                state = State::SingleQuoted;
                statement_start = false;
                index += 1;
            }
            State::Normal if bytes[index] == b'"' => {
                state = State::DoubleQuoted;
                statement_start = false;
                index += 1;
            }
            State::Normal if bytes[index] == b'@' && gtk_identifier_follows(&bytes, index + 1) => {
                if statement_start
                    && identifier_at(&bytes, index + 1, b"define-color")
                    && let Some(end) = bytes[index..].iter().position(|byte| *byte == b';')
                {
                    let end = index + end;
                    mask_as_comment(&mut bytes, index, end);
                    statement_start = true;
                    index = end + 1;
                    continue;
                }
                if !statement_start {
                    bytes[index] = b'_';
                }
                statement_start = false;
                index += 1;
            }
            State::Normal => {
                if matches!(bytes[index], b'{' | b'}' | b';') {
                    statement_start = true;
                } else if !bytes[index].is_ascii_whitespace() {
                    statement_start = false;
                }
                index += 1;
            }
            State::Comment if bytes[index..].starts_with(b"*/") => {
                state = State::Normal;
                index += 2;
            }
            State::Comment => index += 1,
            State::SingleQuoted | State::DoubleQuoted if bytes[index] == b'\\' => {
                index = (index + 2).min(bytes.len());
            }
            State::SingleQuoted | State::DoubleQuoted if matches!(bytes[index], b'\n' | b'\r') => {
                let line = bytes[..index].iter().filter(|byte| **byte == b'\n').count() + 1;
                return Err(format!("unescaped newline in string on line {line}"));
            }
            State::SingleQuoted if bytes[index] == b'\'' => {
                state = State::Normal;
                index += 1;
            }
            State::DoubleQuoted if bytes[index] == b'"' => {
                state = State::Normal;
                index += 1;
            }
            State::SingleQuoted | State::DoubleQuoted => index += 1,
        }
    }
    String::from_utf8(bytes).map_err(|_| "internal UTF-8 masking failure".to_owned())
}

fn gtk_identifier_follows(bytes: &[u8], index: usize) -> bool {
    bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(*byte, b'_' | b'-'))
}

fn identifier_at(bytes: &[u8], index: usize, expected: &[u8]) -> bool {
    bytes.get(index..index + expected.len()) == Some(expected)
        && bytes
            .get(index + expected.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'_' | b'-'))
}

fn mask_as_comment(bytes: &mut [u8], start: usize, end: usize) {
    for byte in &mut bytes[start..=end] {
        if !matches!(*byte, b'\n' | b'\r') {
            *byte = b' ';
        }
    }
    bytes[start] = b'/';
    bytes[start + 1] = b'*';
    bytes[end - 1] = b'*';
    bytes[end] = b'/';
}

fn collect_css_errors(
    node: tree_sitter::Node<'_>,
    original: &str,
    label: &str,
    problems: &mut Vec<String>,
) {
    if problems.len() >= 8 {
        return;
    }
    if node.is_error() || node.is_missing() {
        let point = node.start_position();
        problems.push(if node.is_missing() {
            format!(
                "{label} syntax error at line {}, column {}: missing `{}`",
                point.row + 1,
                point.column + 1,
                node.kind()
            )
        } else {
            format!(
                "{label} syntax error at line {}, column {} near `{}`",
                point.row + 1,
                point.column + 1,
                node.utf8_text(original.as_bytes()).unwrap_or(node.kind())
            )
        });
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_css_errors(child, original, label, problems);
        if problems.len() >= 8 {
            break;
        }
    }
}

fn validate_safe_lines(content: &str) -> Vec<String> {
    if content
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        vec!["content contains unsafe control characters".to_owned()]
    } else {
        Vec::new()
    }
}

fn validate_scalar(content: &str) -> Vec<String> {
    let mut problems = validate_safe_lines(content);
    let value = content.strip_suffix('\n').unwrap_or(content);
    if value.contains('\n') {
        problems.push("scalar output contains more than one line".to_owned());
    }
    problems
}

fn collect_lua_errors(node: tree_sitter::Node<'_>, content: &str, problems: &mut Vec<String>) {
    if problems.len() >= 8 {
        return;
    }
    if node.is_error() || node.is_missing() {
        let point = node.start_position();
        problems.push(if node.is_missing() {
            format!(
                "Lua syntax error at line {}, column {}: missing `{}`",
                point.row + 1,
                point.column + 1,
                node.kind()
            )
        } else {
            format!(
                "Lua syntax error at line {}, column {} near `{}`",
                point.row + 1,
                point.column + 1,
                node.utf8_text(content.as_bytes()).unwrap_or(node.kind())
            )
        });
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_lua_errors(child, content, problems);
        if problems.len() >= 8 {
            break;
        }
    }
}

fn collect_shell_errors(node: tree_sitter::Node<'_>, content: &str, problems: &mut Vec<String>) {
    if problems.len() >= 8 {
        return;
    }
    if node.is_error() || node.is_missing() {
        let point = node.start_position();
        problems.push(if node.is_missing() {
            format!(
                "shell syntax error at line {}, column {}: missing `{}`",
                point.row + 1,
                point.column + 1,
                node.kind()
            )
        } else {
            format!(
                "shell syntax error at line {}, column {} near `{}`",
                point.row + 1,
                point.column + 1,
                node.utf8_text(content.as_bytes()).unwrap_or(node.kind())
            )
        });
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_shell_errors(child, content, problems);
        if problems.len() >= 8 {
            break;
        }
    }
}

pub(crate) fn validate_kdl(content: &str, dialect: KdlDialect) -> Vec<String> {
    let result = match dialect {
        KdlDialect::V2 => content.parse::<kdl::KdlDocument>().map(|_| ()),
        KdlDialect::V1 => kdl::KdlDocument::parse_v1(content).map(|_| ()),
    };
    match result {
        Ok(()) => Vec::new(),
        Err(error) => {
            let mut problems = Vec::new();
            for diagnostic in &error.diagnostics {
                problems.push(format!("invalid KDL {}: {diagnostic}", dialect.label()));
            }
            if problems.is_empty() {
                problems.push(format!("invalid KDL {}", dialect.label()));
            }
            problems
        }
    }
}

fn validate_ini(content: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with(';')
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
            || trimmed.contains('=')
        {
            continue;
        }
        problems.push(format!(
            "line {}: not a section, comment, or key=value: `{trimmed}`",
            index + 1
        ));
    }
    problems
}

/// Hyprland/mango-style config: `key = value` assignments (the key may be
/// dotted or colon-namespaced), `name {` block openers, bare `}` closers,
/// comments, and blank lines. Checks brace balance too.
fn validate_conf_lines(content: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut depth: i64 = 0;
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if trimmed == "}" {
            depth -= 1;
            if depth < 0 {
                problems.push(format!("line {}: unbalanced `}}`", index + 1));
                depth = 0;
            }
            continue;
        }
        if let Some(before) = trimmed.strip_suffix('{') {
            if before.trim().is_empty() {
                problems.push(format!("line {}: block opener without a name", index + 1));
            }
            depth += 1;
            continue;
        }
        if trimmed.contains('=') {
            continue;
        }
        problems.push(format!(
            "line {}: not an assignment, block, or comment: `{trimmed}`",
            index + 1
        ));
    }
    if depth != 0 {
        problems.push(format!("{depth} unclosed block(s)"));
    }
    problems
}

fn validate_mango(content: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            problems.push(format!("line {}: expected a Mango assignment", index + 1));
            continue;
        };
        let name = name.trim();
        if name.is_empty()
            || value
                .chars()
                .any(|character| matches!(character, '\n' | '\r'))
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            problems.push(format!("line {}: invalid Mango directive", index + 1));
        }
        let fields = value.split(',').count();
        let minimum = match name {
            "bind" | "mousebind" => 3,
            "gesturebind" => 4,
            "monitorrule" | "tagrule" | "windowrule" | "layerrule" => 2,
            _ => 1,
        };
        if fields < minimum {
            problems.push(format!("line {}: `{name}` has too few fields", index + 1));
        }
    }
    problems
}

fn validate_kanshi(content: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut profile = false;
    let mut output = false;
    let mut profile_outputs = 0usize;
    let mut output_fields: Vec<&str> = Vec::new();
    let mut output_line = 0usize;
    for (index, raw) in content.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("profile ") && !profile && !output {
            if !valid_kanshi_header(line, "profile ") {
                problems.push(format!("line {line_number}: invalid Kanshi profile name"));
            }
            profile = true;
            profile_outputs = 0;
            continue;
        }
        if line.starts_with("output ") && profile && !output {
            if !valid_kanshi_header(line, "output ") {
                problems.push(format!("line {line_number}: invalid Kanshi output name"));
            }
            output = true;
            output_fields.clear();
            output_line = line_number;
            continue;
        }
        if line == "}" {
            if output {
                for required in ["mode", "scale", "transform"] {
                    if !output_fields.contains(&required) {
                        problems.push(format!(
                            "line {output_line}: Kanshi output is missing `{required}`"
                        ));
                    }
                }
                output = false;
                profile_outputs += 1;
            } else if profile {
                if profile_outputs == 0 {
                    problems.push(format!(
                        "line {line_number}: Kanshi profile contains no outputs"
                    ));
                }
                profile = false;
            } else {
                problems.push(format!("line {line_number}: unmatched closing brace"));
            }
            continue;
        }
        let (field, valid) = if !output {
            (None, false)
        } else if let Some(value) = line.strip_prefix("mode ") {
            (Some("mode"), valid_kanshi_mode(value))
        } else if let Some(value) = line.strip_prefix("scale ") {
            (Some("scale"), valid_positive_number(value, 1000.0))
        } else if let Some(value) = line.strip_prefix("position ") {
            (Some("position"), valid_kanshi_position(value))
        } else if let Some(value) = line.strip_prefix("transform ") {
            (
                Some("transform"),
                [
                    "normal",
                    "90",
                    "180",
                    "270",
                    "flipped",
                    "flipped-90",
                    "flipped-180",
                    "flipped-270",
                ]
                .contains(&value),
            )
        } else {
            (None, false)
        };
        if !valid {
            problems.push(format!("line {line_number}: invalid Kanshi statement"));
        } else if let Some(field) = field {
            if output_fields.contains(&field) {
                problems.push(format!(
                    "line {line_number}: duplicate Kanshi output field `{field}`"
                ));
            } else {
                output_fields.push(field);
            }
        }
    }
    if profile || output {
        problems.push("unclosed Kanshi block".to_owned());
    }
    problems
}

fn valid_kanshi_header(line: &str, prefix: &str) -> bool {
    let Some(name) = line
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(" {"))
    else {
        return false;
    };
    let Some(name) = name
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return false;
    };
    !name.is_empty()
        && !name
            .chars()
            .any(|character| character.is_control() || character == '"')
}

fn valid_kanshi_mode(value: &str) -> bool {
    let Some((size, refresh)) = value
        .strip_suffix("Hz")
        .and_then(|value| value.split_once('@'))
    else {
        return false;
    };
    let Some((width, height)) = size.split_once('x') else {
        return false;
    };
    width.parse::<u32>().is_ok_and(|value| value > 0)
        && height.parse::<u32>().is_ok_and(|value| value > 0)
        && valid_positive_number(refresh, 1000.0)
}
fn valid_positive_number(value: &str, maximum: f64) -> bool {
    value
        .parse::<f64>()
        .is_ok_and(|value| value.is_finite() && value > 0.0 && value <= maximum)
}
fn valid_kanshi_position(value: &str) -> bool {
    value
        .split_once(',')
        .is_some_and(|(x, y)| x.parse::<i64>().is_ok() && y.parse::<i64>().is_ok())
}

/// Strip `//` line comments and `/* */` block comments outside strings.
fn strip_json_comments(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
                i += 1;
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                let start = i;
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 >= bytes.len() {
                    let line = input[..start].bytes().filter(|byte| *byte == b'\n').count() + 1;
                    return Err(format!(
                        "unterminated block comment starting on line {line}"
                    ));
                }
                i += 2;
            }
            // Accept trailing commas before } or ] without consuming whitespace.
            ',' => {
                let mut j = i + 1;
                while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                    j += 1;
                }
                if !(j < bytes.len() && (bytes[j] == b'}' || bytes[j] == b']')) {
                    out.push(c);
                }
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_formats() {
        assert!(validate_format("json", "{\"a\": 1}").is_empty());
        assert!(!validate_format("json", "{a: 1}").is_empty());
        assert!(validate_format("jsonc", "// c\n{\"a\": 1,}\n").is_empty());
        let jsonc = validate_format("jsonc", "{\"a\": 1} /* unterminated");
        assert!(
            jsonc
                .iter()
                .any(|problem| problem.contains("unterminated block comment"))
        );
        assert!(validate_format("toml", "[section]\nkey = 1\n").is_empty());
        assert!(!validate_format("toml", "key = [\n").is_empty());
        assert!(validate_format("xml", "<root><child /></root>").is_empty());
        assert!(!validate_format("xml", "<root>").is_empty());
        assert!(validate_format("ini", "[s]\nk=v\n# c\n").is_empty());
        assert!(!validate_format("ini", "bare\n").is_empty());
        assert!(validate_format("kdl-v2", "node 1").is_empty());
        assert!(validate_format("kdl-v1", "node \"a\"").is_empty());
        assert!(validate_format("hypr", "general {\n  gaps_in = 5\n}\n").is_empty());
        assert!(!validate_format("hypr", "general {\n").is_empty());
        assert!(validate_format("hyprlock", "general {\n  hide_cursor = true\n}\n").is_empty());
        assert!(validate_format("hypridle", "listener {\n  timeout = 300\n}\n").is_empty());
        assert!(validate_format("mango", "bind=SUPER,Return,spawn,terminal\n").is_empty());
        assert!(!validate_format("mango", "bind=SUPER\n").is_empty());
        assert!(validate_format("kanshi", "profile \"p\" {\noutput \"eDP-1\" {\nmode 1920x1080@60.0Hz\nscale 1.0\ntransform normal\n}\n}\n").is_empty());
        assert!(!validate_format("kanshi", "profile \"p\" {\nmode broken\n}\n").is_empty());
        assert!(
            !validate_format(
                "kanshi",
                "profile \"p\" {\noutput \"eDP-1\" {\nmode 1920x1080@60.0Hz\n}\n}\n"
            )
            .is_empty()
        );
        assert!(!validate_format("kanshi", "profile \"p\" {\noutput \"eDP-1\" {\nmode 1920x1080@60.0Hz\nscale 1.0\nscale 2.0\ntransform normal\n}\n}\n").is_empty());
        assert!(validate_format("lua", "local x = { [\"a\"] = true }\n").is_empty());
        assert!(!validate_format("lua", "local =\n").is_empty());
        assert!(validate_format("scalar", "value\n").is_empty());
        assert!(!validate_format("scalar", "value\n\n").is_empty());
        assert!(validate_format("shell", "if true; then echo ok; fi\n").is_empty());
        assert!(!validate_format("shell", "if true; then\n").is_empty());
    }

    #[test]
    fn gtk_css_accepts_gtk3_and_gtk4_extensions() {
        assert!(validator_known("gtk-css"));
        let gtk = r#"
@define-color foreground #f8f8f2;
@define-color accent alpha(@foreground, 0.8);
@import url("colors.css");

window#waybar,
.osd-window {
    color: @foreground;
    background-color: alpha(@accent, 0.2);
    border-color: mix(@foreground, @accent, 0.5);
    box-shadow: 0 1px 2px shade(@accent, 0.7);
    -gtk-icon-shadow: 0 1px @foreground;
    -gtk-icon-transform: scale(0.9);
}

button:hover {
    -gtk-icon-source: -gtk-icontheme("system-search-symbolic");
    background-image: image(@accent);
}
"#;
        let problems = validate_format("gtk-css", gtk);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(!validate_format("css", gtk).is_empty());
    }

    #[test]
    fn gtk_css_keeps_at_signs_inside_comments_and_strings() {
        let gtk = r#"
/* @foreground is documentation here. */
label {
    content: "@foreground";
    color: @foreground;
}
"#;
        assert!(validate_format("gtk-css", gtk).is_empty());
    }

    #[test]
    fn gtk_css_rejects_malformed_or_unsafe_input() {
        for invalid in [
            "label { color: @foreground;",
            "label { color @foreground; }",
            "label { color: alpha(@accent, 0.2; }",
            "label { color: @; }",
            "label { content: \"unterminated; }",
            "label { content: \"bad\nstring\"; }",
            "/* unterminated comment",
            "label { color: red; }}",
            "label { color: red; }\0",
        ] {
            let problems = validate_format("gtk-css", invalid);
            assert!(!problems.is_empty(), "unexpectedly accepted: {invalid:?}");
        }
    }

    #[test]
    fn gtk_css_diagnostics_retain_original_positions() {
        let problems = validate_format("gtk-css", "label {\n  color: alpha(@accent, 0.2;\n}\n");
        assert!(
            problems.iter().any(|problem| problem.contains("line 2")),
            "{problems:?}"
        );
    }
}
