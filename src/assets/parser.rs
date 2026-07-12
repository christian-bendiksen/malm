//! Parsing and validation for KDL `assets` blocks.
//! URLs require HTTPS and SHA-256 checks default to required.

use crate::assets::{ArchiveFormat, AssetConfig, AssetEntry, AssetManifest};
use crate::config::kdl::{bool_prop, reject_unknown_children, reject_unknown_props};
use crate::source::git::reject_url_userinfo;
use anyhow::{Context, Result};
use kdl::KdlNode;
use std::collections::HashSet;

impl AssetManifest {
    pub fn from_node(node: &KdlNode) -> Result<Self> {
        reject_unknown_props(node, &["require-sha256"])?;
        reject_unknown_children(node, &["asset"])?;

        let argc = node.iter().filter(|e| e.name().is_none()).count();
        if argc != 0 {
            anyhow::bail!("`assets` node: expected no positional arguments, found {argc}");
        }

        let require_sha256 = if node.get("require-sha256").is_some() {
            bool_prop(node, "require-sha256")?
        } else {
            true
        };

        let mut assets = Vec::new();
        if let Some(children) = node.children() {
            for child in children.nodes() {
                if child.name().value() == "asset" {
                    assets.push(parse_asset_entry(child)?);
                }
            }
        }

        let mut seen: HashSet<&str> = HashSet::new();
        for a in &assets {
            if !seen.insert(a.name.as_str()) {
                anyhow::bail!("assets: duplicate asset name `{}`", a.name);
            }
        }

        Ok(AssetManifest {
            config: AssetConfig { require_sha256 },
            assets,
        })
    }
}

fn parse_asset_entry(node: &KdlNode) -> Result<AssetEntry> {
    reject_unknown_props(node, &[])?;
    let argc = node.iter().filter(|e| e.name().is_none()).count();
    if argc != 1 {
        anyhow::bail!(
            "`asset` node: expected exactly one positional argument (the name), found {argc}"
        );
    }
    reject_unknown_children(
        node,
        &[
            "url",
            "dst",
            "format",
            "sha256",
            "installed-check",
            "refresh-font-cache",
            "require-sha256",
        ],
    )?;

    let name = node
        .get(0)
        .and_then(|v| v.as_string())
        .map(|s| s.to_owned())
        .ok_or_else(|| anyhow::anyhow!("`asset` node: missing name argument"))?;
    validate_asset_name(&name)?;

    let url = req_child_str(node, "url", &name)?;
    if !url.starts_with("https://") {
        anyhow::bail!("asset `{name}`: url must use https://");
    }
    reject_url_userinfo(&url).with_context(|| format!("asset `{name}`"))?;

    let sha256 = opt_child_str(node, "sha256", &name)?;
    if let Some(value) = sha256.as_deref() {
        validate_sha256(&name, value)?;
    }

    Ok(AssetEntry {
        url,
        dst: req_child_str(node, "dst", &name)?,
        format: {
            let s = req_child_str(node, "format", &name)?;
            parse_format(&s)?
        },
        sha256,
        installed_check: opt_child_str(node, "installed-check", &name)?,
        refresh_font_cache: child_bool(node, "refresh-font-cache", &name)?,
        require_sha256: opt_child_bool(node, "require-sha256", &name)?,
        name,
    })
}

fn parse_format(s: &str) -> Result<ArchiveFormat> {
    match s {
        "zip" => Ok(ArchiveFormat::Zip),
        "tar-xz" | "tar.xz" => Ok(ArchiveFormat::TarXz),
        "tar-gz" | "tar.gz" => Ok(ArchiveFormat::TarGz),
        other => {
            anyhow::bail!(
                "unknown archive format `{other}` (expected `zip`, `tar-xz`, or `tar-gz`)"
            )
        }
    }
}

fn child_nodes<'a>(node: &'a KdlNode, child: &str) -> Vec<&'a KdlNode> {
    node.children()
        .map(|doc| {
            doc.nodes()
                .iter()
                .filter(|n| n.name().value() == child)
                .collect()
        })
        .unwrap_or_default()
}

fn validate_leaf_child(
    node: &KdlNode,
    asset_name: &str,
    child: &str,
    expected_args: usize,
) -> Result<()> {
    reject_unknown_props(node, &[])?;
    reject_unknown_children(node, &[])?;

    let argc = node.iter().filter(|entry| entry.name().is_none()).count();
    if argc != expected_args {
        anyhow::bail!(
            "asset `{asset_name}`: `{child}` expects exactly {expected_args} positional argument(s), found {argc}"
        );
    }

    Ok(())
}

fn req_child_str(node: &KdlNode, child: &str, asset_name: &str) -> Result<String> {
    let matches = child_nodes(node, child);

    if matches.len() != 1 {
        anyhow::bail!(
            "asset `{asset_name}`: expected exactly one `{child}`, found {}",
            matches.len()
        );
    }

    let child_node = matches[0];
    validate_leaf_child(child_node, asset_name, child, 1)?;

    child_node
        .get(0)
        .and_then(|v| v.as_string())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("asset `{asset_name}`: `{child}` must be a string"))
}

fn opt_child_str(node: &KdlNode, child: &str, asset_name: &str) -> Result<Option<String>> {
    let matches = child_nodes(node, child);

    if matches.len() > 1 {
        anyhow::bail!(
            "asset `{asset_name}`: expected at most one `{child}`, found {}",
            matches.len()
        );
    }

    let Some(child_node) = matches.first() else {
        return Ok(None);
    };

    validate_leaf_child(child_node, asset_name, child, 1)?;

    child_node
        .get(0)
        .and_then(|v| v.as_string())
        .map(|s| Some(s.to_owned()))
        .ok_or_else(|| anyhow::anyhow!("asset `{asset_name}`: `{child}` must be a string"))
}

fn child_bool(node: &KdlNode, child: &str, asset_name: &str) -> Result<bool> {
    let matches = child_nodes(node, child);

    if matches.len() > 1 {
        anyhow::bail!(
            "asset `{asset_name}`: expected at most one `{child}`, found {}",
            matches.len()
        );
    }

    let Some(child_node) = matches.first() else {
        return Ok(false);
    };

    validate_leaf_child(child_node, asset_name, child, 1)?;

    child_node.get(0).and_then(|v| v.as_bool()).ok_or_else(|| {
        anyhow::anyhow!("asset `{asset_name}`: `{child}` must be a boolean (#true or #false)")
    })
}

fn opt_child_bool(node: &KdlNode, child: &str, asset_name: &str) -> Result<Option<bool>> {
    let matches = child_nodes(node, child);

    if matches.len() > 1 {
        anyhow::bail!(
            "asset `{asset_name}`: expected at most one `{child}`, found {}",
            matches.len()
        );
    }

    let Some(child_node) = matches.first() else {
        return Ok(None);
    };

    validate_leaf_child(child_node, asset_name, child, 1)?;

    child_node
        .get(0)
        .and_then(|v| v.as_bool())
        .map(Some)
        .ok_or_else(|| {
            anyhow::anyhow!("asset `{asset_name}`: `{child}` must be a boolean (#true or #false)")
        })
}

fn validate_sha256(asset_name: &str, value: &str) -> Result<()> {
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("asset `{asset_name}`: sha256 must be exactly 64 hexadecimal characters");
    }

    Ok(())
}

fn validate_asset_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("asset name must contain only [A-Za-z0-9_-], got: {name:?}");
    }
    Ok(())
}
