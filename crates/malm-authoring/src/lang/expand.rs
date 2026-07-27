//! Expands module outputs into files, symlinks, and validated KDL artifacts.

use crate::lang::artifact::{Artifact, ArtifactContent};
use crate::lang::ast::{
    ConflictPolicy, FragmentCardinality, KdlConfigBody, KdlDialect, MissingSourcePolicy,
    OutputNode, Predicate,
};
use crate::lang::budget::Budget;
use crate::lang::diag::{Diagnostics, Span, codes};
use crate::lang::resolve::{ResolvedModule, ResolvedWorkspace};
use crate::lang::scope::Scope;
use crate::lang::typecheck::{TypedInstance, resolve_source};
use crate::lang::value::Value;
use kdl::{KdlDocument, KdlEntry, KdlNode};
use std::path::PathBuf;

/// Non-artifact outputs that reference existing files.
#[derive(Debug)]
pub struct FileOut {
    pub source: PathBuf,
    pub source_label: String,
    pub to: String,
    pub optional: bool,
    pub executable: bool,
    pub on_conflict: ConflictPolicy,
    pub instance: String,
    pub span: Span,
}

#[derive(Debug)]
pub struct DirOut {
    pub source: PathBuf,
    pub source_label: String,
    pub to: Option<String>,
    pub optional: bool,
    pub executable: bool,
    pub on_conflict: ConflictPolicy,
    pub ignore: Vec<String>,
    #[allow(dead_code)]
    pub instance: String,
}

#[derive(Debug)]
pub struct SymlinkOut {
    pub source: String,
    pub to: String,
    pub optional: bool,
    /// Policy used when plan lowering checks for a missing target.
    #[allow(dead_code)]
    pub if_missing: MissingSourcePolicy,
    pub instance: String,
    pub span: Span,
}

/// Outputs produced by one compilation.
#[derive(Debug, Default)]
pub struct GeneratedArtifacts {
    pub artifacts: Vec<Artifact>,
    pub files: Vec<FileOut>,
    pub dirs: Vec<DirOut>,
    pub symlinks: Vec<SymlinkOut>,
}

pub struct Expander<'a> {
    pub workspace: &'a ResolvedWorkspace,
    pub sources: &'a crate::AuthoringSourceSetV1,
    /// Sorted, unique requirement subjects emitted by `@requirements`.
    pub profile_requirements: &'a [String],
    /// Selectable, non-abstract profile names emitted by `@profiles`.
    pub profile_names: &'a [String],
    pub budget: &'a mut Budget,
    pub diagnostics: &'a mut Diagnostics,
}

struct KdlExpansion<'a> {
    module: &'a ResolvedModule,
    instance: &'a TypedInstance,
    span: Span,
    stack: Vec<String>,
    payload_bytes: u64,
}

impl Expander<'_> {
    /// Expand one module instance into generated outputs.
    pub fn expand_instance(
        &mut self,
        module: &ResolvedModule,
        instance: &TypedInstance,
        scope: &mut Scope,
        out: &mut GeneratedArtifacts,
    ) {
        for output in module.outputs() {
            if self.budget.exhausted() {
                return;
            }
            self.expand_output(module, instance, scope, output, 0, out);
        }
    }

    fn budget_check(
        &mut self,
        result: Result<(), crate::lang::budget::BudgetError>,
        span: Span,
    ) -> bool {
        match result {
            Ok(()) => true,
            Err(error) => {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(span));
                false
            }
        }
    }

    /// Evaluate a predicate after type-checking has verified its operands.
    fn eval_predicate(&mut self, scope: &Scope, predicate: &Predicate) -> Option<bool> {
        let reference = predicate.reference();
        let value = scope.lookup(&reference.name);
        predicate.eval(value).or_else(|| {
            if let Some(value) = value {
                self.diagnostics.error_at(
                    codes::WHEN_PREDICATE,
                    format!(
                        "`{}` cannot evaluate a {} value",
                        predicate.label(),
                        value.type_label()
                    ),
                    reference.span,
                );
            } else {
                self.diagnostics.error_at(
                    codes::UNDEFINED_REF,
                    format!("`{}` is not defined", reference.name),
                    reference.span,
                );
            }
            None
        })
    }

    fn expand_output(
        &mut self,
        module: &ResolvedModule,
        instance: &TypedInstance,
        scope: &mut Scope,
        output: &OutputNode,
        depth: usize,
        out: &mut GeneratedArtifacts,
    ) {
        if self.budget.exhausted() {
            return;
        }
        match output {
            OutputNode::When(when) => {
                let check = self.budget.check_nesting(depth + 1);
                if !self.budget_check(check, when.span) {
                    return;
                }
                let Some(truth) = self.eval_predicate(scope, &when.predicate) else {
                    return;
                };
                let branch = if truth { &when.then } else { &when.otherwise };
                for child in branch {
                    self.expand_output(module, instance, scope, child, depth + 1, out);
                }
            }
            OutputNode::KdlConfig(config) => {
                let KdlConfigBody::Document { nodes, span, .. } = &config.body;
                let mut expansion = KdlExpansion {
                    module,
                    instance,
                    span: *span,
                    stack: Vec::new(),
                    payload_bytes: 0,
                };
                let content =
                    self.generate_kdl_document(&mut expansion, scope, nodes, config.dialect, depth);
                let Some(content) = content else {
                    return;
                };
                out.artifacts.push(Artifact {
                    to: config.to.clone(),
                    content: ArtifactContent::Bytes(content),
                    executable: false,
                    format: format!("kdl-{}", config.dialect.label()),
                    transforms: config.transforms.clone(),
                    instance: instance.alias.clone(),
                    module: module.decl.name.clone(),
                    span: config.span,
                });
            }
            OutputNode::ConfigFile(config_file) => {
                let Some(content) = crate::lang::config_file::render(
                    &config_file.body,
                    scope,
                    self.budget,
                    self.diagnostics,
                ) else {
                    return;
                };
                out.artifacts.push(Artifact {
                    to: config_file.to.clone(),
                    content: ArtifactContent::Bytes(content),
                    executable: false,
                    format: config_file.body.format_name().to_owned(),
                    transforms: config_file.transforms.clone(),
                    instance: instance.alias.clone(),
                    module: module.decl.name.clone(),
                    span: config_file.span,
                });
            }
            OutputNode::Render(render) => {
                let to = match &render.to {
                    crate::lang::render::PathExpr::Literal(path) => path.clone(),
                    crate::lang::render::PathExpr::FString { raw, span } => {
                        let lookup = |name: &str| scope.lookup(name).cloned();
                        match crate::lang::text::render_template_with_limit(
                            raw,
                            crate::lang::text::TemplateSyntax::V3,
                            &lookup,
                            self.budget.limits().max_artifact_bytes,
                        ) {
                            Ok(path) if !path.is_empty() && !path.chars().any(char::is_control) => {
                                path
                            }
                            Ok(_) => {
                                self.diagnostics.error_at(codes::OUTPUT_PATH,
                                        "interpolated render path is empty or contains control characters", *span);
                                return;
                            }
                            Err(message) => {
                                self.diagnostics.error_at(codes::TEMPLATE, message, *span);
                                return;
                            }
                        }
                    }
                };
                let content = if let Some(renderer) = &render.renderer {
                    let Some(document) = crate::lang::render::component_document(
                        &render.body,
                        scope,
                        self.budget,
                        self.diagnostics,
                    ) else {
                        return;
                    };
                    ArtifactContent::Component {
                        renderer: renderer.clone(),
                        format: render.body.format.format_name().to_owned(),
                        document,
                    }
                } else {
                    let (file_requests, fragment_requests) =
                        crate::lang::render::collect_resources(&render.body.items);
                    let mut resources = crate::lang::render::RenderResources {
                        requirements: self.profile_requirements.to_vec(),
                        profiles: self.profile_names.to_vec(),
                        ..Default::default()
                    };
                    for (path, span) in file_requests {
                        let resolved =
                            match resolve_source(&path, &render.dir, &self.workspace.source_root) {
                                Ok(resolved) => resolved,
                                Err(message) => {
                                    self.diagnostics.error_at(codes::OUTPUT_PATH, message, span);
                                    return;
                                }
                            };
                        let Some(text) = self.read_render_file(&resolved, span) else {
                            return;
                        };
                        resources.files.insert(path, text);
                    }
                    for (fragment, span) in fragment_requests {
                        let Some((composed, _format)) =
                            self.compose_fragment(module, instance, &fragment, span)
                        else {
                            return;
                        };
                        resources.fragments.insert(fragment, composed);
                    }
                    let Some(content) = crate::lang::render::render_output(
                        &render.body,
                        scope,
                        self.budget,
                        self.diagnostics,
                        &resources,
                    ) else {
                        return;
                    };
                    ArtifactContent::Bytes(content)
                };
                out.artifacts.push(Artifact {
                    to,
                    content,
                    executable: render.executable,
                    format: render.body.format.format_name().to_owned(),
                    transforms: render.transforms.clone(),
                    instance: instance.alias.clone(),
                    module: module.decl.name.clone(),
                    span: render.span,
                });
            }
            OutputNode::Each(each) => {
                let check = self.budget.check_nesting(depth + 1);
                if !self.budget_check(check, each.span) {
                    return;
                }
                let Some(items) = self.loop_items(scope, &each.source.name, each.span) else {
                    return;
                };
                let iter_budget = self.budget.count_iterations(items.len() as u64);
                if !self.budget_check(iter_budget, each.span) {
                    return;
                }
                for (key, item) in items {
                    let keyed = key.is_some();
                    if let Some(key) = key {
                        scope.push_binding(format!("{}.key", each.binding), Value::String(key));
                    }
                    scope.push_binding(&each.binding, item);
                    for child in &each.body {
                        self.expand_output(module, instance, scope, child, depth + 1, out);
                    }
                    scope.pop_binding();
                    if keyed {
                        scope.pop_binding();
                    }
                    if self.budget.exhausted() {
                        return;
                    }
                }
            }
            OutputNode::Range(range) => {
                let count = range
                    .through
                    .checked_sub(range.from)
                    .and_then(|value| value.checked_add(1));
                let Some(count) = count.filter(|value| *value > 0) else {
                    return;
                };
                let checks = self
                    .budget
                    .check_nesting(depth + 1)
                    .and_then(|_| self.budget.check_range(count))
                    .and_then(|_| self.budget.count_iterations(count as u64));
                if !self.budget_check(checks, range.span) {
                    return;
                }
                for number in range.from..=range.through {
                    scope.push_binding(&range.binding, Value::Int(number));
                    for child in &range.body {
                        self.expand_output(module, instance, scope, child, depth + 1, out);
                    }
                    scope.pop_binding();
                    if self.budget.exhausted() {
                        return;
                    }
                }
            }
            OutputNode::File(file) => {
                let source =
                    match resolve_source(&file.source, &file.dir, &self.workspace.source_root) {
                        Ok(path) => path,
                        Err(message) => {
                            self.diagnostics
                                .error_at(codes::OUTPUT_PATH, message, file.span);
                            return;
                        }
                    };
                out.files.push(FileOut {
                    source,
                    source_label: file.source.clone(),
                    to: file.to.clone(),
                    optional: file.optional,
                    executable: file.executable,
                    on_conflict: file.on_conflict,
                    instance: instance.alias.clone(),
                    span: file.span,
                });
            }
            OutputNode::Dir(dir) => {
                let source =
                    match resolve_source(&dir.source, &dir.dir, &self.workspace.source_root) {
                        Ok(path) => path,
                        Err(message) => {
                            self.diagnostics
                                .error_at(codes::OUTPUT_PATH, message, dir.span);
                            return;
                        }
                    };
                out.dirs.push(DirOut {
                    source,
                    source_label: dir.source.clone(),
                    to: dir.to.clone(),
                    optional: dir.optional,
                    executable: dir.executable,
                    on_conflict: dir.on_conflict,
                    ignore: dir.ignore.clone(),
                    instance: instance.alias.clone(),
                });
            }
            OutputNode::Symlink(symlink) => {
                let source = match &symlink.source {
                    crate::lang::ast::SymlinkSource::Literal(path) => path.clone(),
                    crate::lang::ast::SymlinkSource::Ref(reference) => {
                        match scope.lookup(&reference.name) {
                            Some(Value::Path(path)) => path.clone(),
                            Some(Value::String(path)) => path.clone(),
                            Some(Value::Null) => return, // A cleared optional produces no link.
                            Some(other) => {
                                self.diagnostics.error_at(
                                    codes::TYPE_MISMATCH,
                                    format!(
                                        "symlink `source=` requires a path, found {}",
                                        other.type_label()
                                    ),
                                    reference.span,
                                );
                                return;
                            }
                            None => {
                                self.diagnostics.error_at(
                                    codes::UNDEFINED_REF,
                                    format!("`{}` is not defined", reference.name),
                                    reference.span,
                                );
                                return;
                            }
                        }
                    }
                };
                out.symlinks.push(SymlinkOut {
                    source,
                    to: symlink.to.clone(),
                    optional: symlink.optional,
                    if_missing: symlink.if_missing,
                    instance: instance.alias.clone(),
                    span: symlink.span,
                });
            }
        }
    }

    fn read_render_file(&mut self, path: &std::path::Path, span: Span) -> Option<String> {
        // Captured sources have validated relative paths, so lookup cannot
        // escape the source set or access the filesystem.
        let allowance = match self.budget.begin_render_file() {
            Ok(allowance) => allowance,
            Err(error) => {
                self.diagnostics
                    .push(error.into_diagnostic().with_span(span));
                return None;
            }
        };
        let Some(bytes) = self.sources.get_path(path) else {
            self.diagnostics.error_at(
                codes::EMIT,
                format!("read {}: not captured", path.display()),
                span,
            );
            return None;
        };
        if bytes.len() as u64 > allowance {
            let check = self.budget.count_render_bytes(allowance.saturating_add(1));
            let _ = self.budget_check(check, span);
            return None;
        }
        let check = self.budget.count_render_bytes(bytes.len() as u64);
        if !self.budget_check(check, span) {
            return None;
        }
        match std::str::from_utf8(bytes) {
            Ok(text) => Some(text.to_owned()),
            Err(_) => {
                self.diagnostics.error_at(
                    codes::EMIT,
                    format!("{} is not valid UTF-8", path.display()),
                    span,
                );
                None
            }
        }
    }

    /// Returns list items without keys or collection items in declaration order.
    /// Collection items expose their key through `<binding>.key`.
    fn loop_items(
        &mut self,
        scope: &Scope,
        name: &str,
        span: Span,
    ) -> Option<Vec<(Option<String>, Value)>> {
        let value = scope.lookup(name)?.clone();
        match value {
            Value::List(items) => {
                let check = self.budget.check_collection_size(items.len());
                if !self.budget_check(check, span) {
                    return None;
                }
                Some(items.into_iter().map(|item| (None, item)).collect())
            }
            Value::Collection(collection) => {
                let check = self.budget.check_collection_size(collection.len());
                if !self.budget_check(check, span) {
                    return None;
                }
                Some(
                    collection
                        .items
                        .into_iter()
                        .map(|item| (Some(item.key), item.value))
                        .collect(),
                )
            }
            other => {
                self.diagnostics.error_at(
                    codes::LOOP_SOURCE,
                    format!(
                        "`@for-each` requires a list or collection, found {}",
                        other.type_label()
                    ),
                    span,
                );
                None
            }
        }
    }

    /// Composes a fragment by reading and concatenating its sources in order.
    /// KDL formats validate each piece before composition so a broken
    /// profile fragment is reported at its own path.
    fn compose_fragment(
        &mut self,
        module: &ResolvedModule,
        instance: &TypedInstance,
        fragment_name: &str,
        span: Span,
    ) -> Option<(String, String)> {
        let Some(fragment) = module.fragment(fragment_name) else {
            self.diagnostics.error_at(
                codes::FRAGMENT,
                format!(
                    "module `{}` declares no fragment `{fragment_name}`",
                    module.decl.name
                ),
                span,
            );
            return None;
        };
        let sources = instance
            .fragment_sources
            .get(fragment_name)
            .cloned()
            .unwrap_or_else(|| fragment.defaults.clone());
        if sources.is_empty() && fragment.cardinality == FragmentCardinality::One {
            self.diagnostics.error_at(codes::FRAGMENT,
                    format!(
                        "fragment `{fragment_name}` has no source: it declares no default and no profile supplied one"
                    ), span);
            return None;
        }
        let mut composed = String::new();
        for source in &sources {
            if self.budget.exhausted() {
                return None;
            }
            let resolved =
                match resolve_source(&source.path, &source.base_dir, &self.workspace.source_root) {
                    Ok(path) => path,
                    Err(message) => {
                        self.diagnostics
                            .error_at(codes::OUTPUT_PATH, message, source.span);
                        continue;
                    }
                };
            let Some(text) = self.read_render_file(&resolved, source.span) else {
                continue;
            };
            for problem in crate::lang::artifact::validate_format(&fragment.format, &text) {
                self.diagnostics.error_at(
                    codes::FRAGMENT,
                    format!(
                        "fragment `{fragment_name}` source {}: {problem}",
                        resolved.display()
                    ),
                    source.span,
                );
            }
            let separator = usize::from(!composed.is_empty() && !composed.ends_with('\n'));
            let Some(new_len) = composed
                .len()
                .checked_add(separator)
                .and_then(|len| len.checked_add(text.len()))
            else {
                let check = self.budget.check_artifact_size(u64::MAX);
                let _ = self.budget_check(check, source.span);
                return None;
            };
            let check = self.budget.check_artifact_size(new_len as u64);
            if !self.budget_check(check, source.span) {
                return None;
            }
            if separator != 0 {
                composed.push('\n');
            }
            composed.push_str(&text);
        }
        Some((composed, fragment.format.clone()))
    }

    /// Expand inline target nodes into serialized KDL under the selected
    /// version.
    fn generate_kdl_document(
        &mut self,
        expansion: &mut KdlExpansion<'_>,
        scope: &mut Scope,
        nodes: &[KdlNode],
        dialect: KdlDialect,
        depth: usize,
    ) -> Option<String> {
        let mut generated = Vec::new();
        self.expand_kdl_nodes(expansion, scope, nodes, depth, &mut generated)?;
        let mut document = KdlDocument::new();
        for node in generated {
            document.nodes_mut().push(node);
        }
        document.autoformat();
        match dialect {
            KdlDialect::V1 => document.ensure_v1(),
            KdlDialect::V2 => document.ensure_v2(),
        }
        let ops = self.budget.count_operations(1);
        if !self.budget_check(ops, expansion.span) {
            return None;
        }
        let mut output_budget = self.budget.begin_output();
        let mut content = String::new();
        {
            use std::fmt::Write as _;
            let _ = write!(output_budget.writer(&mut content), "{document}");
        }
        let check = self.budget.finish_output(&output_budget, content.len());
        self.budget_check(check, expansion.span).then_some(content)
    }

    /// Consumes controls and emits ordinary nodes with references and
    /// interpolations resolved, preserving node and child order.
    fn expand_kdl_nodes(
        &mut self,
        expansion: &mut KdlExpansion<'_>,
        scope: &mut Scope,
        nodes: &[KdlNode],
        depth: usize,
        out: &mut Vec<KdlNode>,
    ) -> Option<()> {
        let mut nodes = nodes.iter().peekable();
        while let Some(node) = nodes.next() {
            if self.budget.exhausted() {
                return None;
            }
            let ops = self.budget.count_operations(1);
            if !self.budget_check(ops, expansion.span) {
                return None;
            }
            match node.name().value() {
                "@if" | "@if-present" | "@if-nonempty" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let predicate = self.raw_when_predicate(node, expansion.span)?;
                    let truth = self.eval_predicate(scope, &predicate)?;
                    let otherwise = if nodes
                        .peek()
                        .is_some_and(|next| next.name().value() == "@else")
                    {
                        Some(nodes.next().expect("peeked"))
                    } else {
                        None
                    };
                    let branch = if truth {
                        crate::lang::kdl_util::child_nodes(node)
                    } else {
                        otherwise
                            .map(crate::lang::kdl_util::child_nodes)
                            .unwrap_or_default()
                    };
                    self.expand_kdl_nodes(expansion, scope, branch, depth + 1, out)?;
                }
                "@for-each" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let binding = node
                        .get(0)
                        .and_then(kdl::KdlValue::as_string)
                        .map(str::to_owned)?;
                    let source_name = node
                        .iter()
                        .find(|e| e.name().is_some_and(|n| n.value() == "in"))
                        .and_then(|e| e.value().as_string())
                        .map(str::to_owned)?;
                    let items = self.loop_items(scope, &source_name, expansion.span)?;
                    let iter_budget = self.budget.count_iterations(items.len() as u64);
                    if !self.budget_check(iter_budget, expansion.span) {
                        return None;
                    }
                    let body: Vec<KdlNode> = crate::lang::kdl_util::child_nodes(node).to_vec();
                    for (key, item) in items {
                        let keyed = key.is_some();
                        if let Some(key) = key {
                            scope.push_binding(format!("{binding}.key"), Value::String(key));
                        }
                        scope.push_binding(&binding, item);
                        let result = self.expand_kdl_nodes(expansion, scope, &body, depth + 1, out);
                        scope.pop_binding();
                        if keyed {
                            scope.pop_binding();
                        }
                        result?;
                    }
                }
                "@for-range" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let binding = node
                        .get(0)
                        .and_then(kdl::KdlValue::as_string)
                        .map(str::to_owned)?;
                    let from = node
                        .get("from")
                        .and_then(kdl::KdlValue::as_integer)
                        .and_then(|value| i64::try_from(value).ok());
                    let through = node
                        .get("through")
                        .and_then(kdl::KdlValue::as_integer)
                        .and_then(|value| i64::try_from(value).ok());
                    let (Some(from), Some(through)) = (from, through) else {
                        self.diagnostics.error_at(
                            codes::NODE_SHAPE,
                            "`@for-range` bounds must fit in 64-bit integers",
                            expansion.span,
                        );
                        return None;
                    };
                    let iterations = range_iterations(from, through)?;
                    let range_check = self.budget.check_range(iterations);
                    if !self.budget_check(range_check, expansion.span) {
                        return None;
                    }
                    let iter_budget = self.budget.count_iterations(iterations as u64);
                    if !self.budget_check(iter_budget, expansion.span) {
                        return None;
                    }
                    let body: Vec<KdlNode> = crate::lang::kdl_util::child_nodes(node).to_vec();
                    for n in from..=through {
                        scope.push_binding(&binding, Value::Int(n));
                        let result = self.expand_kdl_nodes(expansion, scope, &body, depth + 1, out);
                        scope.pop_binding();
                        result?;
                    }
                }
                "@insert-documents" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let collection_name = node
                        .get(0)
                        .and_then(kdl::KdlValue::as_string)
                        .map(str::to_owned)?;
                    let Some(Value::Collection(collection)) =
                        scope.lookup(&collection_name).cloned()
                    else {
                        self.diagnostics.error_at(
                            codes::TYPE_MISMATCH,
                            format!("`{collection_name}` is not a collection"),
                            expansion.span,
                        );
                        continue;
                    };
                    let stack_name = format!("collection:{collection_name}");
                    if let Some(start) = expansion.stack.iter().position(|name| name == &stack_name)
                    {
                        let mut cycle = expansion.stack[start..].to_vec();
                        cycle.push(stack_name);
                        self.diagnostics.error_at(
                            codes::KDL_GEN,
                            format!("@insert-documents cycle detected: {}", cycle.join(" -> ")),
                            expansion.span,
                        );
                        return None;
                    }
                    let check = self.budget.check_collection_size(collection.items.len());
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let ops = self.budget.count_operations(collection.items.len() as u64);
                    if !self.budget_check(ops, expansion.span) {
                        return None;
                    }
                    expansion.stack.push(stack_name);
                    for item in &collection.items {
                        if let Value::KdlDocument(doc) = &item.value {
                            if let Err(diagnostic) =
                                crate::lang::parse::validate_structural_kdl_document(
                                    item.span.file,
                                    doc.nodes(),
                                )
                            {
                                self.diagnostics.push(diagnostic);
                                return None;
                            }
                            // Spliced documents may contain controls, references, and
                            // interpolations, so expand them like inline nodes.
                            self.expand_kdl_nodes(expansion, scope, doc.nodes(), depth + 1, out)?;
                        }
                    }
                    expansion.stack.pop();
                }
                "@include-fragment" => {
                    let check = self.budget.check_nesting(depth + 1);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    let fragment_name = node
                        .get("fragment")
                        .and_then(kdl::KdlValue::as_string)
                        .map(str::to_owned)?;
                    let stack_name = format!("fragment:{fragment_name}");
                    if let Some(start) = expansion.stack.iter().position(|name| name == &stack_name)
                    {
                        let mut cycle = expansion.stack[start..].to_vec();
                        cycle.push(stack_name);
                        self.diagnostics.error_at(
                            codes::KDL_GEN,
                            format!("KDL expansion cycle detected: {}", cycle.join(" -> ")),
                            expansion.span,
                        );
                        return None;
                    }
                    let included = self.load_kdl_fragment(
                        expansion.module,
                        expansion.instance,
                        &fragment_name,
                        expansion.span,
                    )?;
                    expansion.stack.push(stack_name);
                    self.expand_kdl_nodes(expansion, scope, included.nodes(), depth + 1, out)?;
                    expansion.stack.pop();
                }
                "@else" => {
                    self.diagnostics.error_at(
                        codes::NODE_SHAPE,
                        "`@else` must immediately follow an `@if`, `@if-present`, or `@if-nonempty` sibling",
                        expansion.span,
                    );
                }
                _ => {
                    let expanded = self.expand_plain_node(expansion, scope, node, depth)?;
                    let payload = kdl_node_payload_bytes(&expanded);
                    let Some(total) = expansion.payload_bytes.checked_add(payload) else {
                        let check = self.budget.check_output_size(u64::MAX);
                        let _ = self.budget_check(check, expansion.span);
                        return None;
                    };
                    let check = self.budget.check_output_size(total);
                    if !self.budget_check(check, expansion.span) {
                        return None;
                    }
                    expansion.payload_bytes = total;
                    let nodes_budget = self.budget.count_generated_nodes(1);
                    if !self.budget_check(nodes_budget, expansion.span) {
                        return None;
                    }
                    out.push(expanded);
                }
            }
        }
        Some(())
    }

    /// Expand one ordinary target node: resolve `(ref)` entries to
    /// typed scalars, interpolate composite strings, recurse into children.
    fn expand_plain_node(
        &mut self,
        expansion: &mut KdlExpansion<'_>,
        scope: &mut Scope,
        node: &KdlNode,
        depth: usize,
    ) -> Option<KdlNode> {
        let escaped_target = (node.name().value() == "node")
            .then(|| crate::lang::kdl_util::escaped_node_target(node))
            .flatten();
        let escaped_name = escaped_target.and_then(|(_, entry)| entry.value().as_string());
        let mut generated = node.clone();
        if let Some(name) = escaped_name {
            generated.set_name(name.to_owned());
        }
        generated.entries_mut().clear();
        for (index, entry) in node.iter().enumerate() {
            if escaped_target.is_some_and(|(target_index, _)| index == target_index) {
                continue;
            }
            let value = if crate::lang::kdl_util::is_ref(entry) {
                let name = entry.value().as_string().unwrap_or_default();
                let Some(value) = scope.lookup(name).cloned() else {
                    self.diagnostics.error_at(
                        codes::UNDEFINED_REF,
                        format!("`{name}` is not defined"),
                        expansion.span,
                    );
                    return None;
                };
                match value_to_kdl(&value) {
                    Ok(kdl_value) => kdl_value,
                    Err(message) => {
                        self.diagnostics.error_at(
                            codes::TYPE_MISMATCH,
                            format!("`{name}`: {message}"),
                            expansion.span,
                        );
                        return None;
                    }
                }
            } else if let kdl::KdlValue::String(s) = entry.value() {
                if s.contains("{{") {
                    match crate::lang::text::render_template_with_limit(
                        s,
                        crate::lang::text::TemplateSyntax::V3,
                        &|name| scope.lookup(name).cloned(),
                        self.budget.limits().max_artifact_bytes,
                    ) {
                        Ok(rendered) => kdl::KdlValue::String(rendered),
                        Err(message) => {
                            self.diagnostics
                                .error_at(codes::TEMPLATE, message, expansion.span);
                            return None;
                        }
                    }
                } else {
                    entry.value().clone()
                }
            } else {
                entry.value().clone()
            };
            let mut generated_entry = if crate::lang::kdl_util::is_ref(entry) {
                match entry.name() {
                    Some(prop) => KdlEntry::new_prop(prop.clone(), value),
                    None => KdlEntry::new(value),
                }
            } else {
                let mut cloned = entry.clone();
                cloned.set_value(value);
                cloned
            };
            generated_entry.set_span(entry.span());
            generated.entries_mut().push(generated_entry);
        }
        if let Some(children) = node.children() {
            let mut expanded_children = Vec::new();
            self.expand_kdl_nodes(
                expansion,
                scope,
                children.nodes(),
                depth + 1,
                &mut expanded_children,
            )?;
            let mut child_doc = KdlDocument::new();
            for child in expanded_children {
                child_doc.nodes_mut().push(child);
            }
            generated.set_children(child_doc);
        }
        Some(generated)
    }

    fn load_kdl_fragment(
        &mut self,
        module: &ResolvedModule,
        instance: &TypedInstance,
        fragment_name: &str,
        span: Span,
    ) -> Option<KdlDocument> {
        let Some(fragment) = module.fragment(fragment_name) else {
            self.diagnostics.error_at(
                codes::FRAGMENT,
                format!(
                    "module `{}` declares no fragment `{fragment_name}`",
                    module.decl.name
                ),
                span,
            );
            return None;
        };
        if fragment.cardinality != FragmentCardinality::One
            || !matches!(fragment.format.as_str(), "kdl-v1" | "kdl-v2")
        {
            return None;
        }
        let sources = instance
            .fragment_sources
            .get(fragment_name)
            .unwrap_or(&fragment.defaults);
        let [source] = sources.as_slice() else {
            self.diagnostics.error_at(
                codes::FRAGMENT,
                format!("inline fragment `{fragment_name}` requires exactly one source"),
                span,
            );
            return None;
        };
        let resolved =
            match resolve_source(&source.path, &source.base_dir, &self.workspace.source_root) {
                Ok(path) => path,
                Err(message) => {
                    self.diagnostics
                        .error_at(codes::OUTPUT_PATH, message, source.span);
                    return None;
                }
            };
        let text = self.read_render_file(&resolved, source.span)?;
        let parsed = match fragment.format.as_str() {
            "kdl-v1" => KdlDocument::parse_v1(&text),
            "kdl-v2" => text.parse::<KdlDocument>(),
            _ => unreachable!("format checked above"),
        };
        match parsed {
            Ok(document) => {
                if let Err(diagnostic) = crate::lang::parse::validate_structural_kdl_document(
                    source.span.file,
                    document.nodes(),
                ) {
                    self.diagnostics
                        .push(diagnostic.with_span(source.span).with_note(format!(
                            "while validating fragment `{fragment_name}` source {}",
                            resolved.display()
                        )));
                    return None;
                }
                Some(document)
            }
            Err(error) => {
                self.diagnostics.error_at(
                    codes::FRAGMENT,
                    format!(
                        "fragment `{fragment_name}` source {} is not valid {}: {error}",
                        resolved.display(),
                        fragment.format
                    ),
                    source.span,
                );
                None
            }
        }
    }

    fn raw_when_predicate(&mut self, node: &KdlNode, span: Span) -> Option<Predicate> {
        match crate::lang::kdl_util::parse_condition(span.file, node) {
            Ok(predicate) => Some(predicate),
            Err(diagnostic) => {
                self.diagnostics.push(diagnostic);
                None
            }
        }
    }
}

fn range_iterations(from: i64, through: i64) -> Option<i64> {
    if through < from {
        return None;
    }
    through.checked_sub(from)?.checked_add(1)
}

fn value_to_kdl(value: &Value) -> Result<kdl::KdlValue, String> {
    match value {
        Value::Bool(b) => Ok(kdl::KdlValue::Bool(*b)),
        Value::Int(i) => Ok(kdl::KdlValue::Integer(*i as i128)),
        Value::Float(x) => Ok(kdl::KdlValue::Float(*x)),
        Value::String(s) | Value::Path(s) => Ok(kdl::KdlValue::String(s.clone())),
        Value::Null => Err("value is #null; guard the reference with `@if-present`".to_owned()),
        other => Err(format!(
            "a `(ref)` inserts a typed scalar, found {}",
            other.type_label()
        )),
    }
}

/// Estimates a generated node's serialized bytes, excluding children that are
/// counted separately. This catches repeated large values before a complete
/// `KdlDocument` exceeds the output budget. The bounded final serializer
/// accounts for quotes, escapes, and framing.
fn kdl_node_payload_bytes(node: &KdlNode) -> u64 {
    let mut bytes = node.name().value().len() as u64;
    for entry in node.iter() {
        bytes = bytes.saturating_add(entry.name().map_or(0, |name| name.value().len() as u64));
        bytes = bytes.saturating_add(match entry.value() {
            kdl::KdlValue::String(value) => value.len() as u64,
            _ => 0,
        });
    }
    bytes
}
