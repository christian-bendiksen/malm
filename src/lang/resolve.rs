//! Resolves module extensions, slots, and profile inheritance. Parents are
//! processed in written order, children override ancestors, and unresolved
//! sibling conflicts are errors. Instance aliases identify modules across
//! layers, and slot replacement is explicit.

use crate::lang::ast::{
    CollectionPatch, ExtendModule, FragmentDecl, FragmentOp, GlobalVar, InputDecl, ModuleDecl,
    OutputNode, ParsedWorkspace, ProfileDecl, ProfileItem, RequirementNode, SlotDecl, SlotMax,
    WithEntry,
};
use crate::lang::diag::{Diagnostic, Diagnostics, Span, codes};
use crate::lang::value::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

/// A module with all its extensions merged in.
#[derive(Debug)]
pub struct ResolvedModule {
    pub decl: ModuleDecl,
    /// Outputs contributed by extensions (after the module's own).
    pub extra_outputs: Vec<OutputNode>,
}

impl ResolvedModule {
    pub fn inputs(&self) -> &[InputDecl] {
        &self.decl.inputs
    }

    pub fn input(&self, name: &str) -> Option<&InputDecl> {
        self.decl.inputs.iter().find(|i| i.name == name)
    }

    pub fn fragment(&self, name: &str) -> Option<&FragmentDecl> {
        self.decl.fragments.iter().find(|f| f.name == name)
    }

    pub fn requires(&self) -> &[RequirementNode] {
        &self.decl.requires
    }

    pub fn outputs(&self) -> impl Iterator<Item = &OutputNode> {
        self.decl.outputs.iter().chain(self.extra_outputs.iter())
    }
}

/// The fully resolved workspace: modules merged, profile graph validated.
#[derive(Debug)]
pub struct ResolvedWorkspace {
    pub modules: BTreeMap<String, ResolvedModule>,
    pub slots: BTreeMap<String, SlotDecl>,
    pub profiles: Vec<ProfileDecl>,
    /// Unique `global.*` design tokens.
    pub globals: BTreeMap<String, GlobalVar>,
    /// The repository root against which bare (non-`./`) sources resolve.
    pub source_root: std::path::PathBuf,
    /// Trusted local loads may expose the host name as a non-optional string.
    pub machine_hostname_trusted: bool,
}

impl ResolvedWorkspace {
    pub fn profile(&self, name: &str) -> Option<&ProfileDecl> {
        self.profiles.iter().find(|p| p.name == name)
    }

    pub fn profile_names(&self) -> Vec<&str> {
        self.profiles.iter().map(|p| p.name.as_str()).collect()
    }
}

pub fn resolve_workspace(
    parsed: ParsedWorkspace,
    source_root: std::path::PathBuf,
    machine_hostname_trusted: bool,
    diagnostics: &mut Diagnostics,
) -> ResolvedWorkspace {
    let ParsedWorkspace {
        modules,
        extensions,
        profiles,
        profile_extensions,
        slots,
        globals,
    } = parsed;

    let mut resolved_modules: BTreeMap<String, ResolvedModule> = BTreeMap::new();
    for module in modules {
        if resolved_modules.contains_key(&module.name) {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!("module `{}` is declared twice", module.name),
                )
                .with_span(module.span),
            );
            continue;
        }
        resolved_modules.insert(
            module.name.clone(),
            ResolvedModule {
                decl: module,
                extra_outputs: Vec::new(),
            },
        );
    }

    for extension in extensions {
        merge_extension(&mut resolved_modules, extension, diagnostics);
    }

    let mut slot_map: BTreeMap<String, SlotDecl> = BTreeMap::new();
    for slot in slots {
        if slot_map.contains_key(&slot.name) {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!("slot `{}` is declared twice", slot.name),
                )
                .with_span(slot.span),
            );
            continue;
        }
        slot_map.insert(slot.name.clone(), slot);
    }

    // Modules referencing unknown slots.
    for module in resolved_modules.values() {
        if let Some(slot) = &module.decl.slot
            && !slot_map.contains_key(slot)
        {
            diagnostics.push(
                Diagnostic::error(
                    codes::SLOT,
                    format!("module `{}` fills unknown slot `{slot}`", module.decl.name),
                )
                .with_span(module.decl.span)
                .with_help(known_names("slot", slot_map.keys().map(String::as_str))),
            );
        }
    }

    let mut merged: Vec<ProfileDecl> = Vec::new();
    for profile in profiles {
        if let Some(existing) = merged.iter().find(|p| p.name == profile.name) {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!("profile `{}` is declared twice", profile.name),
                )
                .with_span(profile.span)
                .with_label("first declared here", existing.span)
                .with_help("use `extend-profile` to add an explicit profile layer"),
            );
        } else {
            merged.push(profile);
        }
    }
    for extension in profile_extensions {
        let Some(profile) = merged.iter_mut().find(|p| p.name == extension.profile) else {
            diagnostics.push(
                Diagnostic::error(
                    codes::UNKNOWN_PROFILE,
                    format!(
                        "`extend-profile` names unknown profile `{}`",
                        extension.profile
                    ),
                )
                .with_span(extension.span),
            );
            continue;
        };
        profile.extends.extend(extension.extends);
        profile.items.extend(extension.items);
    }
    let profiles = merged;
    validate_profile_graph(&profiles, diagnostics);

    let mut global_map: BTreeMap<String, GlobalVar> = BTreeMap::new();
    for var in globals {
        if let Some(existing) = global_map.get(&var.name) {
            if !var.override_existing {
                diagnostics.push(
                    Diagnostic::error(
                        codes::DUPLICATE,
                        format!("global `{}` is declared twice", var.name),
                    )
                    .with_span(var.span)
                    .with_label("first declared here", existing.span)
                    .with_help(
                        "add `override=#true` when replacing an existing global intentionally",
                    ),
                );
            } else if std::mem::discriminant(&existing.value) != std::mem::discriminant(&var.value)
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::TYPE_MISMATCH,
                        format!(
                            "global `{}` override changes its type from {} to {}",
                            var.name,
                            existing.value.type_label(),
                            var.value.type_label()
                        ),
                    )
                    .with_span(var.span)
                    .with_label("original type declared here", existing.span),
                );
            } else {
                global_map.insert(var.name.clone(), var);
            }
        } else if var.override_existing {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!(
                        "global `{}` uses `override=#true` but has no earlier declaration",
                        var.name
                    ),
                )
                .with_span(var.span),
            );
        } else {
            global_map.insert(var.name.clone(), var);
        }
    }

    ResolvedWorkspace {
        modules: resolved_modules,
        slots: slot_map,
        profiles,
        globals: global_map,
        source_root,
        machine_hostname_trusted,
    }
}

fn merge_extension(
    modules: &mut BTreeMap<String, ResolvedModule>,
    extension: ExtendModule,
    diagnostics: &mut Diagnostics,
) {
    let Some(module) = modules.get_mut(&extension.module) else {
        diagnostics.push(
            Diagnostic::error(
                codes::EXTEND_MODULE,
                format!(
                    "`extend-module` names unknown module `{}`",
                    extension.module
                ),
            )
            .with_span(extension.span)
            .with_help(
                "declare the module before extending it; includes are processed in written order",
            ),
        );
        return;
    };
    for input in extension.inputs {
        if let Some(existing) = module.decl.inputs.iter().find(|i| i.name == input.name) {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!(
                        "module `{}`: input `{}` is declared twice (module + extension)",
                        extension.module, input.name
                    ),
                )
                .with_span(input.span)
                .with_label("first declared here", existing.span),
            );
            continue;
        }
        module.decl.inputs.push(input);
    }
    for fragment in extension.fragments {
        if let Some(existing) = module
            .decl
            .fragments
            .iter()
            .find(|f| f.name == fragment.name)
        {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE,
                    format!(
                        "module `{}`: fragment `{}` is declared twice (module + extension)",
                        extension.module, fragment.name
                    ),
                )
                .with_span(fragment.span)
                .with_label("first declared here", existing.span),
            );
            continue;
        }
        module.decl.fragments.push(fragment);
    }
    module.decl.requires.extend(extension.requires);
    module.extra_outputs.extend(extension.outputs);
}

fn known_names<'a>(kind: &str, names: impl Iterator<Item = &'a str>) -> String {
    let mut sorted: Vec<&str> = names.collect();
    sorted.sort_unstable();
    if sorted.is_empty() {
        format!("no {kind}s are declared")
    } else {
        format!("known {kind}s: {}", sorted.join(", "))
    }
}

fn validate_profile_graph(profiles: &[ProfileDecl], diagnostics: &mut Diagnostics) {
    let by_name: HashMap<&str, &ProfileDecl> =
        profiles.iter().map(|p| (p.name.as_str(), p)).collect();
    for profile in profiles {
        let mut seen = HashSet::new();
        for (parent, span) in &profile.extends {
            if !by_name.contains_key(parent.as_str()) {
                diagnostics.push(
                    Diagnostic::error(
                        codes::UNKNOWN_PROFILE,
                        format!(
                            "profile `{}` extends unknown profile `{parent}`",
                            profile.name
                        ),
                    )
                    .with_span(*span)
                    .with_help(known_names("profile", by_name.keys().copied())),
                );
            }
            if !seen.insert(parent.as_str()) {
                diagnostics.push(
                    Diagnostic::error(
                        codes::DUPLICATE,
                        format!("profile `{}` extends `{parent}` twice", profile.name),
                    )
                    .with_span(*span),
                );
            }
        }
    }
    // Cycle detection over the extends graph.
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Visiting,
        Done,
    }
    fn visit<'a>(
        name: &'a str,
        by_name: &HashMap<&'a str, &'a ProfileDecl>,
        states: &mut HashMap<&'a str, State>,
        stack: &mut Vec<&'a str>,
        diagnostics: &mut Diagnostics,
    ) {
        match states.get(name) {
            Some(State::Done) => return,
            Some(State::Visiting) => {
                let cycle_start = stack.iter().position(|n| *n == name).unwrap_or(0);
                let mut chain: Vec<&str> = stack[cycle_start..].to_vec();
                chain.push(name);
                let span = by_name.get(name).map(|p| p.span);
                let mut diag = Diagnostic::error(
                    codes::PROFILE_CYCLE,
                    format!("profile inheritance cycle: {}", chain.join(" -> ")),
                );
                if let Some(span) = span {
                    diag = diag.with_span(span);
                }
                diagnostics.push(diag);
                return;
            }
            None => {}
        }
        states.insert(name, State::Visiting);
        stack.push(name);
        if let Some(profile) = by_name.get(name) {
            for (parent, _) in &profile.extends {
                if by_name.contains_key(parent.as_str()) {
                    visit(parent, by_name, states, stack, diagnostics);
                }
            }
        }
        stack.pop();
        states.insert(name, State::Done);
    }
    let mut states = HashMap::new();
    for profile in profiles {
        visit(
            profile.name.as_str(),
            &by_name,
            &mut states,
            &mut Vec::new(),
            diagnostics,
        );
    }
}

/// Deterministic linearization: parents in written order, depth-first,
/// each ancestor once, the profile itself last.
pub fn linearize<'a>(workspace: &'a ResolvedWorkspace, name: &str) -> Option<Vec<&'a ProfileDecl>> {
    fn walk<'a>(
        workspace: &'a ResolvedWorkspace,
        name: &str,
        seen: &mut HashSet<String>,
        out: &mut Vec<&'a ProfileDecl>,
    ) {
        if seen.contains(name) {
            return;
        }
        let Some(profile) = workspace.profile(name) else {
            return;
        };
        seen.insert(name.to_owned());
        for (parent, _) in &profile.extends {
            walk(workspace, parent, seen, out);
        }
        out.push(profile);
    }
    workspace.profile(name)?;
    let mut out = Vec::new();
    walk(workspace, name, &mut HashSet::new(), &mut out);
    Some(out)
}

/// Ancestor sets distinguish descendant overrides from sibling conflicts.
fn ancestors_of(workspace: &ResolvedWorkspace, name: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack = vec![name.to_owned()];
    while let Some(current) = stack.pop() {
        if let Some(profile) = workspace.profile(&current) {
            for (parent, _) in &profile.extends {
                if out.insert(parent.clone()) {
                    stack.push(parent.clone());
                }
            }
        }
    }
    out
}

/// A layered value with the profile that set it, for conflict detection.
#[derive(Debug, Clone)]
struct Layered<T> {
    value: T,
    profile: String,
    span: Span,
}

/// One activated module instance after profile folding.
#[derive(Debug)]
pub struct ResolvedInstance {
    pub alias: String,
    pub module: String,
    /// Final input overrides, with profile provenance, before type-checking.
    pub with: Vec<(String, Value, Span, String)>,
    /// Fragment operations in application order with their source profiles.
    pub fragment_ops: Vec<(FragmentOp, String)>,
    /// Collection patches in application order.
    pub patches: Vec<(CollectionPatch, String)>,
    /// Record-field patches in application order.
    pub sets: Vec<(crate::lang::ast::SetPatch, String)>,
    /// Where the instance was activated.
    pub span: Span,
}

/// The resolved profile: its linearized chain and active instances in
/// activation order.
#[derive(Debug)]
pub struct ResolvedProfile {
    pub name: String,
    pub chain: Vec<String>,
    pub instances: Vec<ResolvedInstance>,
}

struct InstanceState {
    module: String,
    module_span: Span,
    activated_by: String,
    /// Incomparable writes are retained so a descendant can resolve diamonds.
    with: BTreeMap<String, Vec<Layered<Value>>>,
    fragment_ops: Vec<(FragmentOp, String)>,
    patches: Vec<(CollectionPatch, String)>,
    sets: Vec<(crate::lang::ast::SetPatch, String)>,
    span: Span,
    active: bool,
    order: usize,
}

/// Fold the linearized profile chain into active instances.
pub fn resolve_profile(
    workspace: &ResolvedWorkspace,
    name: &str,
    diagnostics: &mut Diagnostics,
) -> Option<ResolvedProfile> {
    let chain = linearize(workspace, name)?;
    let mut instances: BTreeMap<String, InstanceState> = BTreeMap::new();
    let mut next_order = 0usize;

    for profile in &chain {
        let profile_ancestors = ancestors_of(workspace, &profile.name);
        for item in &profile.items {
            match item {
                ProfileItem::Use(use_decl) => {
                    let alias = use_decl
                        .alias
                        .clone()
                        .unwrap_or_else(|| use_decl.module.clone());
                    if !workspace.modules.contains_key(&use_decl.module) {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::UNKNOWN_MODULE,
                                format!(
                                    "profile `{}` uses unknown module `{}`",
                                    profile.name, use_decl.module
                                ),
                            )
                            .with_span(use_decl.span)
                            .with_help(known_names(
                                "module",
                                workspace.modules.keys().map(String::as_str),
                            )),
                        );
                        continue;
                    }
                    apply_instance_layer(
                        &mut instances,
                        &mut next_order,
                        alias,
                        &use_decl.module,
                        use_decl.span,
                        &use_decl.config.with,
                        &use_decl.config.fragments,
                        &use_decl.config.patches,
                        &use_decl.config.sets,
                        profile,
                        &profile_ancestors,
                        workspace,
                        diagnostics,
                    );
                }
                ProfileItem::Replace(replace) => {
                    let Some(module) = workspace.modules.get(&replace.module) else {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::UNKNOWN_MODULE,
                                format!(
                                    "profile `{}` replaces slot `{}` with unknown module `{}`",
                                    profile.name, replace.slot, replace.module
                                ),
                            )
                            .with_span(replace.span),
                        );
                        continue;
                    };
                    if module.decl.slot.as_deref() != Some(replace.slot.as_str()) {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::SLOT,
                                format!(
                                    "module `{}` does not fill slot `{}` (it fills {})",
                                    replace.module,
                                    replace.slot,
                                    module
                                        .decl
                                        .slot
                                        .as_deref()
                                        .map(|s| format!("slot `{s}`"))
                                        .unwrap_or_else(|| "no slot".to_owned())
                                ),
                            )
                            .with_span(replace.span),
                        );
                        continue;
                    }
                    if let Some(slot_def) = workspace.slots.get(&replace.slot)
                        && !matches!(slot_def.max, SlotMax::Max(1))
                    {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::SLOT,
                                format!(
                                    "`replace` targets slot `{}` with max {}; replace is for single-provider slots — use `use` for multi-provider slots",
                                    replace.slot,
                                    slot_def.max.label()
                                ),
                            )
                            .with_span(replace.span),
                        );
                        continue;
                    }
                    // Deactivate the current provider(s) of the slot.
                    let mut displaced = 0usize;
                    for state in instances.values_mut() {
                        if !state.active {
                            continue;
                        }
                        let provider_slot = workspace
                            .modules
                            .get(&state.module)
                            .and_then(|m| m.decl.slot.as_deref());
                        if provider_slot == Some(replace.slot.as_str()) {
                            state.active = false;
                            displaced += 1;
                        }
                    }
                    if displaced == 0 {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::SLOT,
                                format!(
                                    "profile `{}`: `replace slot=\"{}\"` matched no active provider in the profile chain; use `use` to fill an empty slot",
                                    profile.name, replace.slot
                                ),
                            )
                            .with_span(replace.span),
                        );
                        continue;
                    }
                    let alias = replace
                        .alias
                        .clone()
                        .unwrap_or_else(|| replace.module.clone());
                    apply_instance_layer(
                        &mut instances,
                        &mut next_order,
                        alias,
                        &replace.module,
                        replace.span,
                        &replace.config.with,
                        &replace.config.fragments,
                        &replace.config.patches,
                        &replace.config.sets,
                        profile,
                        &profile_ancestors,
                        workspace,
                        diagnostics,
                    );
                }
            }
        }
    }

    // Unresolved sibling conflicts are errors.
    for (alias, state) in &instances {
        if !state.active {
            continue;
        }
        for (input, layers) in &state.with {
            let Some(first) = layers.first() else {
                continue;
            };
            if let Some(other) = layers
                .iter()
                .skip(1)
                .find(|other| other.value != first.value)
            {
                diagnostics.push(
                    Diagnostic::error(
                        codes::SIBLING_CONFLICT,
                        format!(
                            "profile `{name}`: input `{alias}.{input}` is set to different values by sibling parents `{}` and `{}`",
                            first.profile, other.profile
                        ),
                    )
                    .with_span(first.span)
                    .with_label("also set here", other.span)
                    .with_help(format!(
                        "set `{input}` in profile `{name}` (or a shared descendant) to resolve the conflict"
                    )),
                );
            }
        }
    }

    // Slot multiplicity across the final active set.
    let mut by_slot: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (alias, state) in &instances {
        if !state.active {
            continue;
        }
        if let Some(slot) = workspace
            .modules
            .get(&state.module)
            .and_then(|m| m.decl.slot.as_deref())
        {
            by_slot.entry(slot).or_default().push(alias.as_str());
        }
    }
    for (slot, providers) in by_slot {
        let max = workspace
            .slots
            .get(slot)
            .map_or(SlotMax::Max(1), |def| def.max);
        if !max.permits(providers.len()) {
            diagnostics.error(
                codes::SLOT,
                format!(
                    "profile `{name}` activates {} providers for slot `{slot}` (max {}): {}",
                    providers.len(),
                    max.label(),
                    providers.join(", ")
                ),
            );
        }
    }

    let mut ordered: Vec<(String, InstanceState)> = instances.into_iter().collect();
    ordered.sort_by_key(|(_, state)| state.order);

    Some(ResolvedProfile {
        name: name.to_owned(),
        chain: chain.iter().map(|p| p.name.clone()).collect(),
        instances: ordered
            .into_iter()
            .filter(|(_, state)| state.active)
            .map(|(alias, state)| ResolvedInstance {
                alias,
                module: state.module,
                with: state
                    .with
                    .into_iter()
                    .filter_map(|(input, layers)| {
                        layers
                            .into_iter()
                            .last()
                            .map(|layered| (input, layered.value, layered.span, layered.profile))
                    })
                    .collect(),
                fragment_ops: state.fragment_ops,
                patches: state.patches,
                sets: state.sets,
                span: state.span,
            })
            .collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_instance_layer(
    instances: &mut BTreeMap<String, InstanceState>,
    next_order: &mut usize,
    alias: String,
    module: &str,
    span: Span,
    with: &[WithEntry],
    fragment_ops: &[FragmentOp],
    patches: &[CollectionPatch],
    sets: &[crate::lang::ast::SetPatch],
    profile: &ProfileDecl,
    profile_ancestors: &HashSet<String>,
    _workspace: &ResolvedWorkspace,
    diagnostics: &mut Diagnostics,
) {
    let state = instances.entry(alias.clone()).or_insert_with(|| {
        let order = *next_order;
        *next_order += 1;
        InstanceState {
            module: module.to_owned(),
            module_span: span,
            activated_by: profile.name.clone(),
            with: BTreeMap::new(),
            fragment_ops: Vec::new(),
            patches: Vec::new(),
            sets: Vec::new(),
            span,
            active: true,
            order,
        }
    });
    if state.module != module {
        diagnostics.push(
            Diagnostic::error(
                codes::ALIAS_CONFLICT,
                format!(
                    "alias `{alias}` is used for two different modules: `{}` (in profile `{}`) and `{module}` (in profile `{}`)",
                    state.module, state.activated_by, profile.name
                ),
            )
            .with_span(span)
            .with_label("first used here", state.module_span),
        );
        return;
    }
    // A `use` re-activates an instance a `replace` displaced only if it comes
    // from a later layer; re-activation keeps accumulated config.
    state.active = true;

    for entry in with {
        let layers = state.with.entry(entry.name.clone()).or_default();
        layers.retain(|existing| {
            existing.profile != profile.name && !profile_ancestors.contains(&existing.profile)
        });
        layers.push(Layered {
            value: entry.value.clone(),
            profile: profile.name.clone(),
            span: entry.span,
        });
    }
    for op in fragment_ops {
        state
            .fragment_ops
            .push((clone_fragment_op(op), profile.name.clone()));
    }
    for patch in patches {
        state
            .patches
            .push((clone_patch(patch), profile.name.clone()));
    }
    for set in sets {
        state.sets.push((set.clone(), profile.name.clone()));
    }
}

// These AST operations are not Clone, so rebuild them here.
fn clone_fragment_op(op: &FragmentOp) -> FragmentOp {
    use crate::lang::ast::FragmentOpBody;
    let clone_body = |body: &FragmentOpBody| FragmentOpBody {
        fragment: body.fragment.clone(),
        source: body.source.clone(),
        span: body.span,
    };
    match op {
        FragmentOp::Replace(body) => FragmentOp::Replace(clone_body(body)),
        FragmentOp::Append(body) => FragmentOp::Append(clone_body(body)),
    }
}

fn clone_patch(patch: &CollectionPatch) -> CollectionPatch {
    use crate::lang::ast::PatchOp;
    CollectionPatch {
        collection: patch.collection.clone(),
        ops: patch
            .ops
            .iter()
            .map(|op| match op {
                PatchOp::Replace { key, value, span } => PatchOp::Replace {
                    key: key.clone(),
                    value: value.clone(),
                    span: *span,
                },
                PatchOp::Append { key, value, span } => PatchOp::Append {
                    key: key.clone(),
                    value: value.clone(),
                    span: *span,
                },
                PatchOp::Remove {
                    key,
                    optional,
                    span,
                } => PatchOp::Remove {
                    key: key.clone(),
                    optional: *optional,
                    span: *span,
                },
                PatchOp::ReplaceAll { items, span } => PatchOp::ReplaceAll {
                    items: items.clone(),
                    span: *span,
                },
            })
            .collect(),
        span: patch.span,
    }
}
