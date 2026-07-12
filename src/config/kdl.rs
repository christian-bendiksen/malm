//! Low-level KDL helpers: reject unknown/duplicate props and children, and
//! typed accessors for args and props.

use anyhow::Result;
use kdl::KdlNode;

pub(crate) fn reject_unknown_props(node: &KdlNode, allowed: &[&str]) -> Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    for entry in node.iter() {
        if let Some(key) = entry.name() {
            let name = key.value();
            if !allowed.contains(&name) {
                anyhow::bail!(
                    "`{}` node: unknown property `{name}`{}",
                    node.name().value(),
                    if allowed.is_empty() {
                        String::new()
                    } else {
                        format!(" (allowed: {})", allowed.join(", "))
                    }
                );
            }
            if seen.contains(&name) {
                anyhow::bail!(
                    "`{}` node: duplicate property `{name}`",
                    node.name().value()
                );
            }
            seen.push(name);
        }
    }
    Ok(())
}
pub(crate) fn reject_unknown_children(node: &KdlNode, allowed: &[&str]) -> Result<()> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    for child in children.nodes() {
        let name = child.name().value();
        if !allowed.contains(&name) {
            anyhow::bail!(
                "`{}` node: unknown child `{name}`{}",
                node.name().value(),
                if allowed.is_empty() {
                    String::new()
                } else {
                    format!(" (allowed: {})", allowed.join(", "))
                }
            );
        }
    }
    Ok(())
}

pub(crate) fn bool_prop(node: &KdlNode, prop: &str) -> Result<bool> {
    match node.get(prop) {
        None => Ok(false),
        Some(v) => v.as_bool().ok_or_else(|| {
            anyhow::anyhow!(
                "`{}` node: property `{prop}` must be a boolean (#true or #false)",
                node.name().value()
            )
        }),
    }
}

pub(super) fn req_str_arg(node: &KdlNode) -> Result<String> {
    expect_arg_count(node, 1)?;
    node.get(0)
        .and_then(|v| v.as_string())
        .map(|s| s.to_owned())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "`{}` node: missing required string argument",
                node.name().value()
            )
        })
}

pub(super) fn expect_arg_count(node: &KdlNode, expected: usize) -> Result<()> {
    let count = node.iter().filter(|e| e.name().is_none()).count();
    if count != expected {
        anyhow::bail!(
            "`{}` node: expected {expected} positional argument(s), found {count}",
            node.name().value()
        );
    }
    Ok(())
}
pub(super) fn req_str_prop(node: &KdlNode, prop: &str) -> Result<String> {
    let Some(value) = node.get(prop) else {
        anyhow::bail!(
            "`{}` node: missing required property `{prop}`",
            node.name().value()
        );
    };
    value.as_string().map(|s| s.to_owned()).ok_or_else(|| {
        anyhow::anyhow!(
            "`{}` node: property `{prop}` must be a string",
            node.name().value()
        )
    })
}
pub(super) fn opt_str_prop(node: &KdlNode, prop: &str) -> Result<Option<String>> {
    let Some(value) = node.get(prop) else {
        return Ok(None);
    };
    value
        .as_string()
        .map(|s| Some(s.to_owned()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "`{}` node: property `{prop}` must be a string",
                node.name().value()
            )
        })
}
