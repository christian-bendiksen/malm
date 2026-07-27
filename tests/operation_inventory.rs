mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use common::TestEnv;
use malm::EngineOperation;
use malm_machine::MachineOperationV1;
use quote::ToTokens;

const CLI_INVENTORY: &str = include_str!("../docs/cli-command-inventory.txt");
const ENGINE_INVENTORY: &str = include_str!("../docs/engine-operation-inventory.tsv");
const MACHINE_INVENTORY: &str = include_str!("../docs/machine-operation-inventory.tsv");
const OPERATION_MATRIX: &str = include_str!("../docs/operation-matrix.tsv");

fn enum_variants(path: &Path, enum_name: &str) -> BTreeSet<String> {
    let source = std::fs::read_to_string(path).unwrap();
    let file = syn::parse_file(&source).unwrap();
    file.items
        .iter()
        .find_map(|item| {
            let syn::Item::Enum(item) = item else {
                return None;
            };
            (item.ident == enum_name).then(|| {
                item.variants
                    .iter()
                    .map(|variant| variant.ident.to_string())
                    .collect()
            })
        })
        .unwrap_or_else(|| panic!("missing enum {enum_name} in {}", path.display()))
}

fn exact_inventory(value: &str) -> Vec<(String, String)> {
    value
        .lines()
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 2, "invalid exact inventory row: {line:?}");
            assert!(fields.iter().all(|field| !field.is_empty()));
            (fields[0].to_owned(), fields[1].to_owned())
        })
        .collect()
}

#[derive(Debug)]
struct EngineInventoryRow {
    variant: String,
    identifier: String,
    facades: Vec<String>,
}

fn engine_inventory() -> Vec<EngineInventoryRow> {
    ENGINE_INVENTORY
        .lines()
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 3, "invalid Engine inventory row: {line:?}");
            assert!(fields.iter().all(|field| !field.is_empty()));
            let facades = fields[2].split(',').map(str::to_owned).collect::<Vec<_>>();
            assert!(!facades.is_empty());
            EngineInventoryRow {
                variant: fields[0].to_owned(),
                identifier: fields[1].to_owned(),
                facades,
            }
        })
        .collect()
}

fn help_commands(help: &str) -> BTreeSet<String> {
    let commands = help
        .split_once("Commands:\n")
        .expect("Clap help has a Commands section")
        .1
        .split_once("\nOptions:")
        .expect("Clap help has an Options section")
        .0;
    commands
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
        .collect()
}

fn camel_to_kebab(value: &str) -> String {
    let mut result = String::new();
    for (index, character) in value.chars().enumerate() {
        if index != 0 && character.is_ascii_uppercase() {
            result.push('-');
        }
        result.push(character.to_ascii_lowercase());
    }
    result
}

#[derive(Debug)]
struct CliGraph {
    paths: BTreeSet<String>,
    leaves: BTreeSet<String>,
}

fn cli_graph(path: &Path) -> CliGraph {
    let source = std::fs::read_to_string(path).unwrap();
    let file = syn::parse_file(&source).unwrap();
    let enums = file
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Enum(item) = item else {
                return None;
            };
            Some((item.ident.to_string(), item))
        })
        .collect::<BTreeMap<_, _>>();
    let mut graph = CliGraph {
        paths: BTreeSet::new(),
        leaves: BTreeSet::new(),
    };

    fn visit(
        enum_name: &str,
        parent: &str,
        enums: &BTreeMap<String, &syn::ItemEnum>,
        graph: &mut CliGraph,
    ) {
        let item = enums
            .get(enum_name)
            .unwrap_or_else(|| panic!("missing command enum {enum_name}"));
        for variant in &item.variants {
            let command = camel_to_kebab(&variant.ident.to_string());
            let path = if parent.is_empty() {
                command
            } else {
                format!("{parent} {command}")
            };
            assert!(
                graph.paths.insert(path.clone()),
                "duplicate CLI path {path}"
            );
            let child = variant.fields.iter().find_map(|field| {
                let is_subcommand = field.attrs.iter().any(|attribute| {
                    attribute.path().is_ident("command")
                        && attribute
                            .meta
                            .to_token_stream()
                            .to_string()
                            .contains("subcommand")
                });
                if !is_subcommand {
                    return None;
                }
                let syn::Type::Path(path) = &field.ty else {
                    panic!("subcommand field has a non-path type");
                };
                Some(
                    path.path
                        .segments
                        .last()
                        .expect("subcommand type has a segment")
                        .ident
                        .to_string(),
                )
            });
            if let Some(child) = child {
                visit(&child, &path, enums, graph);
            } else {
                assert!(graph.leaves.insert(path));
            }
        }
    }

    visit("TopLevelCmd", "", &enums, &mut graph);
    graph
}

fn direct_children(paths: &BTreeSet<String>, parent: &str) -> BTreeSet<String> {
    paths
        .iter()
        .filter_map(|path| {
            let remainder = if parent.is_empty() {
                path.as_str()
            } else {
                path.strip_prefix(parent)?.strip_prefix(' ')?
            };
            (!remainder.contains(' ')).then(|| remainder.to_owned())
        })
        .collect()
}

fn human_dispatch_mappings(path: &Path) -> BTreeMap<String, String> {
    let source = std::fs::read_to_string(path).unwrap();
    let mut mappings = BTreeMap::new();
    let mut cursor = 0;
    while let Some(relative) = source[cursor..].find("human(") {
        let start = cursor + relative;
        let open = start + "human".len();
        let mut depth = 0_u32;
        let mut in_string = false;
        let mut escaped = false;
        let mut close = None;
        for (offset, character) in source[open..].char_indices() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
                continue;
            }
            match character {
                '"' => in_string = true,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.expect("human call has balanced parentheses");
        let call = &source[open + 1..close];
        let arguments = call.trim_start();
        if let Some(arguments) = arguments.strip_prefix('"') {
            let quote = arguments.find('"').expect("literal command name is closed");
            let command = arguments[..quote].replace('.', " ");
            let cmd = call
                .find("Cmd::")
                .map(|index| &call[index + "Cmd::".len()..])
                .map(|remainder| {
                    remainder
                        .chars()
                        .take_while(|character| character.is_ascii_alphanumeric())
                        .collect::<String>()
                })
                .expect("literal human dispatch constructs a Cmd variant");
            assert!(
                mappings.insert(command.clone(), cmd).is_none(),
                "duplicate human dispatch mapping for {command}"
            );
        }
        cursor = close + 1;
    }
    mappings
}

#[test]
fn cli_inventory_is_exact_across_enums_help_dispatchers_and_matrix() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let inventory = CLI_INVENTORY
        .lines()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(inventory.len(), CLI_INVENTORY.lines().count());

    let graph = cli_graph(&root.join("src/cli/args.rs"));
    assert_eq!(graph.paths, inventory);

    let env = TestEnv::new();
    let groups = std::iter::once("")
        .chain(graph.paths.iter().map(String::as_str).filter(|path| {
            let prefix = format!("{path} ");
            graph
                .paths
                .iter()
                .any(|candidate| candidate.starts_with(&prefix))
        }))
        .collect::<Vec<_>>();
    for group in groups {
        let mut arguments = group.split_whitespace().collect::<Vec<_>>();
        arguments.push("--help");
        let output = env.malm(&arguments);
        assert!(output.status.success(), "help failed below {group:?}");
        assert_eq!(
            help_commands(&String::from_utf8(output.stdout).unwrap()),
            direct_children(&graph.paths, group),
            "Clap help differs below {group:?}"
        );
    }

    let dispatch = human_dispatch_mappings(&root.join("src/cli/args.rs"));
    let directly_mapped_leaves = graph
        .leaves
        .iter()
        .filter(|path| {
            !matches!(
                path.as_str(),
                "machine" | "source lock create" | "source lock update"
            )
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        dispatch.keys().cloned().collect::<BTreeSet<_>>(),
        directly_mapped_leaves
    );
    let arguments = std::fs::read_to_string(root.join("src/cli/args.rs")).unwrap();
    assert!(arguments.contains("LockCmd::Create(_) => \"source.lock.create\""));
    assert!(arguments.contains("LockCmd::Update(_) => \"source.lock.update\""));
    assert!(arguments.contains("\"plan.switch-profile\""));

    let matrix_operations = matrix_rows()
        .into_iter()
        .filter(|row| row.cli_operation != "none")
        .map(|row| row.cli_operation)
        .collect::<BTreeSet<_>>();
    assert_eq!(matrix_operations, graph.leaves);
}

#[test]
fn engine_inventory_is_exact_and_every_matrix_reference_is_real() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let inventory = engine_inventory();
    assert_eq!(inventory.len(), EngineOperation::ALL.len());
    assert_eq!(
        inventory
            .iter()
            .map(|row| (row.variant.clone(), row.identifier.clone()))
            .collect::<Vec<_>>(),
        EngineOperation::ALL
            .iter()
            .map(|operation| (format!("{operation:?}"), operation.as_str().to_owned()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        enum_variants(
            &root.join("crates/malm-engine/src/events.rs"),
            "EngineOperation"
        ),
        inventory.iter().map(|row| row.variant.clone()).collect()
    );

    let identifiers = inventory
        .iter()
        .map(|row| row.identifier.as_str())
        .collect::<BTreeSet<_>>();
    for row in matrix_rows() {
        for field in [row.cli_engine_operations, row.machine_engine_operations] {
            if matches!(field.as_str(), "none" | "request-dependent") {
                continue;
            }
            for operation in field.split(',') {
                assert!(
                    identifiers.contains(operation),
                    "matrix references unknown Engine operation {operation:?}"
                );
            }
        }
    }
}

#[test]
fn every_public_engine_facade_emits_its_exact_inventoried_operation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("crates/malm-engine/src/lib.rs")).unwrap();
    let file = syn::parse_file(&source).unwrap();
    let mut bodies = BTreeMap::<String, String>::new();
    for item in file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        let syn::Type::Path(self_type) = item.self_ty.as_ref() else {
            continue;
        };
        if self_type
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "Engine")
        {
            continue;
        }
        for item in item.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            if matches!(method.vis, syn::Visibility::Public(_)) {
                bodies.insert(
                    method.sig.ident.to_string(),
                    method.block.to_token_stream().to_string(),
                );
            }
        }
    }

    let variants = EngineOperation::ALL
        .iter()
        .map(|operation| format!("{operation:?}"))
        .collect::<BTreeSet<_>>();
    let mut emitted = bodies
        .iter()
        .map(|(method, body)| {
            let operations = variants
                .iter()
                .filter(|variant| body.contains(&format!("EngineOperation :: {variant}")))
                .cloned()
                .collect::<BTreeSet<_>>();
            (method.clone(), operations)
        })
        .collect::<BTreeMap<_, _>>();

    loop {
        let previous = emitted.clone();
        for (method, body) in &bodies {
            for (target, operations) in &previous {
                if method != target && body.contains(&format!("self . {target} (")) {
                    emitted
                        .get_mut(method)
                        .expect("public method was indexed")
                        .extend(operations.iter().cloned());
                }
            }
        }
        if emitted == previous {
            break;
        }
    }

    let operationless = emitted
        .iter()
        .filter(|(_, operations)| operations.is_empty())
        .map(|(method, _)| method.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        operationless,
        BTreeSet::from(["config", "new", "process_facts"])
    );
    emitted.retain(|_, operations| !operations.is_empty());

    let mut expected = BTreeMap::<String, BTreeSet<String>>::new();
    for row in engine_inventory() {
        for facade in row.facades {
            expected
                .entry(facade)
                .or_default()
                .insert(row.variant.clone());
        }
    }
    assert_eq!(emitted, expected);
}

#[derive(Debug, Eq, PartialEq)]
struct SourceContract {
    engine_operations: BTreeSet<String>,
    effect: String,
}

fn source_contracts(
    path: &Path,
    function: &str,
    enum_prefix: &str,
    variants: &BTreeSet<String>,
) -> BTreeMap<String, SourceContract> {
    let source = std::fs::read_to_string(path).unwrap();
    let file = syn::parse_file(&source).unwrap();
    let function_item = file
        .items
        .iter()
        .find_map(|item| {
            let syn::Item::Fn(item) = item else {
                return None;
            };
            (item.sig.ident == function).then_some(item)
        })
        .unwrap_or_else(|| panic!("missing contract function {function}"));
    let arms = function_item
        .block
        .stmts
        .iter()
        .find_map(|statement| {
            let syn::Stmt::Expr(syn::Expr::Match(expression), _) = statement else {
                return None;
            };
            Some(&expression.arms)
        })
        .unwrap_or_else(|| panic!("contract function {function} has no match"));
    let engine_variants = EngineOperation::ALL
        .iter()
        .map(|operation| format!("{operation:?}"))
        .collect::<BTreeSet<_>>();
    let effects = [
        "ReadOnlyInspection",
        "HostWriteExport",
        "PrepareOnly",
        "PrepareWithAcquisition",
        "LockWithAcquisition",
        "MutationWrite",
        "RequestDependent",
    ];
    let mut result = BTreeMap::new();
    for arm in arms {
        let pattern = arm.pat.to_token_stream().to_string();
        let body = arm.body.to_token_stream().to_string();
        let operations = engine_variants
            .iter()
            .filter(|variant| {
                body.contains(&format!("Engine :: {variant}"))
                    || body.contains(&format!("EngineOperation :: {variant}"))
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let effect = effects
            .iter()
            .filter(|effect| body.contains(*effect))
            .copied()
            .collect::<Vec<_>>();
        if effect.is_empty() {
            continue;
        }
        for variant in variants {
            let needle = format!("{enum_prefix} :: {variant}");
            if pattern.ends_with(&needle) || pattern.contains(&format!("{needle} ")) {
                assert_eq!(effect.len(), 1, "{function}::{variant} has no exact effect");
                assert!(
                    result
                        .insert(
                            variant.clone(),
                            SourceContract {
                                engine_operations: operations.clone(),
                                effect: effect[0].to_owned(),
                            },
                        )
                        .is_none(),
                    "{function} maps {variant} more than once"
                );
            }
        }
    }
    result
}

fn top_level_match_arms(path: &Path, function: &str) -> Vec<(String, String)> {
    fn match_expression(expression: &syn::Expr) -> Option<&syn::ExprMatch> {
        match expression {
            syn::Expr::Match(expression) => Some(expression),
            syn::Expr::Try(expression) => match_expression(&expression.expr),
            syn::Expr::Paren(expression) => match_expression(&expression.expr),
            _ => None,
        }
    }

    let source = std::fs::read_to_string(path).unwrap();
    let file = syn::parse_file(&source).unwrap();
    let function_item = file
        .items
        .iter()
        .find_map(|item| {
            let syn::Item::Fn(item) = item else {
                return None;
            };
            (item.sig.ident == function).then_some(item)
        })
        .unwrap_or_else(|| panic!("missing dispatch function {function} in {}", path.display()));
    let expression = function_item
        .block
        .stmts
        .iter()
        .find_map(|statement| match statement {
            syn::Stmt::Expr(expression, _) => match_expression(expression),
            syn::Stmt::Local(local) => local
                .init
                .as_ref()
                .and_then(|init| match_expression(&init.expr)),
            syn::Stmt::Item(_) | syn::Stmt::Macro(_) => None,
        })
        .unwrap_or_else(|| panic!("dispatch function {function} has no top-level match"));
    expression
        .arms
        .iter()
        .map(|arm| {
            (
                arm.pat.to_token_stream().to_string(),
                arm.body.to_token_stream().to_string(),
            )
        })
        .collect()
}

fn source_operation_mapping(
    path: &Path,
    function: &str,
    enum_prefix: &str,
    variants: &BTreeSet<String>,
) -> BTreeMap<String, BTreeSet<String>> {
    let engine_variants = EngineOperation::ALL
        .iter()
        .map(|operation| format!("{operation:?}"))
        .collect::<BTreeSet<_>>();
    let mut result = BTreeMap::new();
    for (pattern, body) in top_level_match_arms(path, function) {
        let operations = engine_variants
            .iter()
            .filter(|variant| body.contains(&format!("EngineOperation :: {variant}")))
            .cloned()
            .collect::<BTreeSet<_>>();
        if operations.is_empty() {
            continue;
        }
        for variant in variants {
            let needle = format!("{enum_prefix} :: {variant}");
            if pattern.ends_with(&needle) || pattern.contains(&format!("{needle} ")) {
                assert!(
                    result.insert(variant.clone(), operations.clone()).is_none(),
                    "{function} maps {variant} more than once"
                );
            }
        }
    }
    result
}

fn source_facade_mapping(
    path: &Path,
    function: &str,
    enum_prefix: &str,
    variants: &BTreeSet<String>,
    facades: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut result = BTreeMap::new();
    for (pattern, body) in top_level_match_arms(path, function) {
        let mut operations = BTreeSet::new();
        for (facade, emitted) in facades {
            if !body.contains(&format!("engine . {facade} (")) {
                continue;
            }
            if facade == "execute_store_v1" {
                if body.contains("StoreRequestV1 :: status") {
                    operations.insert("StoreStatus".to_owned());
                } else if body.contains("StoreRequestV1 :: initialize") {
                    operations.insert("InitializeStore".to_owned());
                } else {
                    panic!("{function} calls execute_store_v1 without an exact request operation");
                }
            } else {
                operations.extend(emitted.iter().cloned());
            }
        }
        if operations.is_empty() {
            continue;
        }
        for variant in variants {
            let needle = format!("{enum_prefix} :: {variant}");
            if pattern.ends_with(&needle) || pattern.contains(&format!("{needle} ")) {
                assert!(
                    result.insert(variant.clone(), operations.clone()).is_none(),
                    "{function} maps {variant} more than once"
                );
            }
        }
    }
    result
}

fn effect_variant(class: &str) -> &'static str {
    match class {
        "read-only-inspection" => "ReadOnlyInspection",
        "host-write-export" => "HostWriteExport",
        "prepare-only" => "PrepareOnly",
        "prepare-with-acquisition" => "PrepareWithAcquisition",
        "lock-with-acquisition" => "LockWithAcquisition",
        "mutation-write" => "MutationWrite",
        "request-dependent" => "RequestDependent",
        other => panic!("unknown operation effect {other:?}"),
    }
}

#[test]
fn operation_matrix_is_the_exact_leaf_and_machine_dispatch_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract_source = root.join("src/cli/contracts.rs");
    let cmd_variants = enum_variants(&root.join("src/cli/args.rs"), "Cmd");
    let store_variants = enum_variants(&root.join("src/cli/args.rs"), "StoreCmd");
    let lock_variants = enum_variants(&root.join("src/cli/args.rs"), "LockCmd");
    let machine_variants = enum_variants(
        &root.join("crates/malm-machine/src/model.rs"),
        "MachineOperationV1",
    );
    let cli = source_contracts(&contract_source, "cli_contract", "Cmd", &cmd_variants);
    let store = source_contracts(
        &contract_source,
        "store_contract",
        "StoreCmd",
        &store_variants,
    );
    let lock = source_contracts(&contract_source, "lock_contract", "LockCmd", &lock_variants);
    let machine = source_contracts(
        &contract_source,
        "machine_contract",
        "Machine",
        &machine_variants,
    );
    assert_eq!(cli.len() + 2, cmd_variants.len());
    assert!(!cli.contains_key("Store"));
    assert!(!cli.contains_key("Lock"));
    assert_eq!(store.len(), store_variants.len());
    assert_eq!(lock.len(), lock_variants.len());
    assert_eq!(
        machine.keys().cloned().collect::<BTreeSet<_>>(),
        machine_variants
    );

    let deployment_dispatch = source_operation_mapping(
        &root.join("src/cli/deployment.rs"),
        "run",
        "Cmd",
        &cmd_variants,
    );
    for (variant, contract) in cli
        .iter()
        .filter(|(variant, _)| variant.as_str() != "Machine")
    {
        assert_eq!(
            deployment_dispatch
                .get(variant)
                .cloned()
                .unwrap_or_default(),
            contract.engine_operations,
            "CLI dispatch arm {variant} is not tied to its exact Engine operation"
        );
    }
    let lock_dispatch = source_operation_mapping(
        &root.join("src/cli/deployment.rs"),
        "run_lock",
        "LockCmd",
        &lock_variants,
    );
    for (variant, contract) in &lock {
        assert_eq!(
            lock_dispatch.get(variant),
            Some(&contract.engine_operations),
            "lock dispatch arm {variant} is not tied to its exact Engine operation"
        );
    }
    let store_dispatch = source_operation_mapping(
        &root.join("src/cli/store.rs"),
        "run",
        "StoreCmd",
        &store_variants,
    );
    for (variant, contract) in &store {
        assert_eq!(
            store_dispatch.get(variant),
            Some(&contract.engine_operations),
            "store dispatch arm {variant} is not tied to its exact Engine operation"
        );
    }
    let machine_execution = source_operation_mapping(
        &root.join("src/cli/machine.rs"),
        "executed_engine_operation",
        "MachineRequestV1",
        &machine_variants,
    );
    for (variant, contract) in &machine {
        assert_eq!(
            machine_execution.get(variant),
            Some(&contract.engine_operations),
            "machine execute arm {variant} is not tied to its exact Engine operation"
        );
    }
    let machine_dispatch = std::fs::read_to_string(root.join("src/cli/machine.rs")).unwrap();
    assert!(
        machine_dispatch
            .contains("contract.assert_engine_operation(executed_engine_operation(request))")
    );

    let mut facade_operations = BTreeMap::<String, BTreeSet<String>>::new();
    for row in engine_inventory() {
        for facade in row.facades {
            facade_operations
                .entry(facade)
                .or_default()
                .insert(row.variant.clone());
        }
    }
    let deployment_facades = source_facade_mapping(
        &root.join("src/cli/deployment.rs"),
        "run",
        "Cmd",
        &cmd_variants,
        &facade_operations,
    );
    for (variant, contract) in cli
        .iter()
        .filter(|(variant, _)| variant.as_str() != "Machine")
    {
        assert_eq!(
            deployment_facades.get(variant).cloned().unwrap_or_default(),
            contract.engine_operations,
            "CLI dispatch arm {variant} calls the wrong Engine facade"
        );
    }
    let lock_facades = source_facade_mapping(
        &root.join("src/cli/deployment.rs"),
        "run_lock",
        "LockCmd",
        &lock_variants,
        &facade_operations,
    );
    for (variant, contract) in &lock {
        assert_eq!(
            lock_facades.get(variant),
            Some(&contract.engine_operations),
            "lock dispatch arm {variant} calls the wrong Engine facade"
        );
    }
    let store_facades = source_facade_mapping(
        &root.join("src/cli/store.rs"),
        "run",
        "StoreCmd",
        &store_variants,
        &facade_operations,
    );
    for (variant, contract) in &store {
        assert_eq!(
            store_facades.get(variant),
            Some(&contract.engine_operations),
            "store dispatch arm {variant} calls the wrong Engine facade"
        );
    }
    let machine_facades = source_facade_mapping(
        &root.join("src/cli/machine.rs"),
        "execute",
        "MachineRequestV1",
        &machine_variants,
        &facade_operations,
    );
    for (variant, contract) in &machine {
        assert_eq!(
            machine_facades.get(variant),
            Some(&contract.engine_operations),
            "machine execute arm {variant} calls the wrong Engine facade"
        );
    }

    let engine_variants = engine_inventory()
        .into_iter()
        .map(|row| (row.identifier, row.variant))
        .collect::<BTreeMap<_, _>>();
    let human_dispatch = human_dispatch_mappings(&root.join("src/cli/args.rs"));
    let machine_names = exact_inventory(MACHINE_INVENTORY)
        .into_iter()
        .map(|(variant, identifier)| (identifier, variant))
        .collect::<BTreeMap<_, _>>();

    for row in matrix_rows() {
        if row.cli_operation == "none" {
            assert_eq!(row.cli_engine_operations, "none");
            assert_eq!(row.class, "none");
        } else if row.cli_operation == "machine" {
            assert_eq!(row.cli_engine_operations, "request-dependent");
            assert_eq!(row.class, "request-dependent");
        } else {
            let cli_contract =
                if let Some(operation) = row.cli_operation.strip_prefix("source lock ") {
                    let variant = lock_variants
                        .iter()
                        .find(|variant| camel_to_kebab(variant) == operation)
                        .unwrap();
                    &lock[variant]
                } else if row.cli_operation == "store status" {
                    &store["Status"]
                } else if row.cli_operation == "store init" {
                    &store["Initialize"]
                } else {
                    let variant = &human_dispatch[&row.cli_operation];
                    &cli[variant]
                };
            let expected_cli_operations = if matches!(
                row.cli_engine_operations.as_str(),
                "request-dependent" | "none"
            ) {
                BTreeSet::new()
            } else {
                row.cli_engine_operations
                    .split(',')
                    .map(|identifier| engine_variants[identifier].clone())
                    .collect()
            };
            let (actual_operations, actual_effect) = if row.cli_operation == "plan switch-profile" {
                assert_eq!(human_dispatch[&row.cli_operation], "Switch");
                (
                    BTreeSet::from(["PrepareProfileSwitchV1".to_owned()]),
                    "PrepareOnly",
                )
            } else {
                (
                    cli_contract.engine_operations.clone(),
                    cli_contract.effect.as_str(),
                )
            };
            assert_eq!(
                actual_operations, expected_cli_operations,
                "CLI Engine mapping differs for {}",
                row.cli_operation
            );
            assert_eq!(
                actual_effect,
                effect_variant(&row.class),
                "CLI effect differs for {}",
                row.cli_operation
            );
        }

        if row.machine_operation == "none" {
            assert_eq!(row.machine_engine_operations, "none");
            continue;
        }
        if row.machine_operation == "request-dependent" {
            assert_eq!(row.machine_engine_operations, "request-dependent");
            continue;
        }
        let variant = &machine_names[&row.machine_operation];
        let expected_machine_operations = row
            .machine_engine_operations
            .split(',')
            .map(|identifier| engine_variants[identifier].clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            machine[variant].engine_operations, expected_machine_operations,
            "machine Engine mapping differs for {}",
            row.machine_operation
        );
    }
}

#[test]
fn machine_inventory_is_exact_across_model_dispatch_codecs_schemas_and_matrix() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let inventory = exact_inventory(MACHINE_INVENTORY);
    assert_eq!(inventory.len(), MachineOperationV1::ALL.len());
    assert_eq!(
        inventory,
        MachineOperationV1::ALL
            .iter()
            .map(|operation| (format!("{operation:?}"), operation.as_str().to_owned()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        enum_variants(
            &root.join("crates/malm-machine/src/model.rs"),
            "MachineOperationV1"
        ),
        inventory
            .iter()
            .map(|(variant, _)| variant.clone())
            .collect()
    );
    let variants = inventory
        .iter()
        .map(|(variant, _)| variant.clone())
        .collect::<BTreeSet<_>>();
    let model = root.join("crates/malm-machine/src/model.rs");
    assert_eq!(enum_variants(&model, "MachineRequestV1"), variants);
    assert_eq!(enum_variants(&model, "MachineResultV1"), variants);
    let codec = root.join("crates/malm-machine/src/codec.rs");
    assert_eq!(enum_variants(&codec, "RequestWireV1"), variants);
    assert_eq!(enum_variants(&codec, "ResultWireV1"), variants);

    let machine_dispatch = std::fs::read_to_string(root.join("src/cli/machine.rs")).unwrap();
    let adapter_contracts = std::fs::read_to_string(root.join("src/cli/contracts.rs")).unwrap();
    for (variant, _) in &inventory {
        assert!(
            adapter_contracts.contains(&format!("Machine::{variant}"))
                || adapter_contracts.contains(&format!("MachineOperationV1::{variant}")),
            "machine access dispatcher omits {variant}"
        );
        assert!(
            machine_dispatch.contains(&format!("MachineRequestV1::{variant}")),
            "machine request dispatcher omits {variant}"
        );
    }

    let expected = inventory
        .iter()
        .map(|(_, identifier)| identifier.clone())
        .collect::<BTreeSet<_>>();
    let request_schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/machine/v1/request.schema.json")).unwrap();
    let request_operations = request_schema["properties"]["request"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reference| {
            let name = reference["$ref"]
                .as_str()
                .unwrap()
                .strip_prefix("#/$defs/")
                .unwrap();
            request_schema["$defs"][name]["properties"]["type"]["const"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(request_operations, expected);

    let server_schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/machine/v1/server.schema.json")).unwrap();
    let event_operations = server_schema["$defs"]["operation"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(event_operations, expected);
    let result_operations =
        server_schema["$defs"]["resultEnvelope"]["properties"]["result"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|result| {
                let result = result["$ref"]
                    .as_str()
                    .and_then(|reference| reference.strip_prefix("#/$defs/"))
                    .map_or(result, |name| &server_schema["$defs"][name]);
                let discriminator = &result["properties"]["type"];
                if let Some(value) = discriminator["const"].as_str() {
                    vec![value.to_owned()]
                } else {
                    discriminator["enum"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_str().unwrap().to_owned())
                        .collect()
                }
            })
            .collect::<BTreeSet<_>>();
    assert_eq!(result_operations, expected);

    let matrix_machine = matrix_rows()
        .into_iter()
        .filter_map(|row| match row.machine_operation.as_str() {
            "none" | "request-dependent" => None,
            operation => Some(operation.to_owned()),
        })
        .collect::<Vec<_>>();
    assert_eq!(matrix_machine.len(), expected.len());
    assert_eq!(
        matrix_machine.into_iter().collect::<BTreeSet<_>>(),
        expected
    );
}

#[derive(Debug, Eq, PartialEq)]
struct MatrixRow {
    cli_operation: String,
    cli_engine_operations: String,
    machine_operation: String,
    machine_engine_operations: String,
    class: String,
}

fn matrix_rows() -> Vec<MatrixRow> {
    let mut lines = OPERATION_MATRIX.lines();
    assert_eq!(
        lines.next(),
        Some(
            "cli_operation\tcli_engine_operations\tmachine_operation\tmachine_engine_operations\tclass"
        )
    );
    let mut classes = BTreeMap::<String, usize>::new();
    let rows = lines
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 5, "invalid operation matrix row: {line:?}");
            assert!(fields.iter().all(|field| !field.is_empty()));
            assert!(matches!(
                fields[4],
                "read-only-inspection"
                    | "host-write-export"
                    | "prepare-only"
                    | "prepare-with-acquisition"
                    | "lock-with-acquisition"
                    | "mutation-write"
                    | "request-dependent"
                    | "none"
            ));
            *classes.entry(fields[4].to_owned()).or_default() += 1;
            MatrixRow {
                cli_operation: fields[0].to_owned(),
                cli_engine_operations: fields[1].to_owned(),
                machine_operation: fields[2].to_owned(),
                machine_engine_operations: fields[3].to_owned(),
                class: fields[4].to_owned(),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows.iter()
            .map(|row| row.cli_operation.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        rows.len(),
        "operation matrix contains duplicate CLI rows"
    );
    assert_eq!(
        classes.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "host-write-export",
            "lock-with-acquisition",
            "mutation-write",
            "none",
            "prepare-only",
            "prepare-with-acquisition",
            "read-only-inspection",
            "request-dependent",
        ])
    );
    for operation in [
        "source lock create",
        "source lock update",
        "plan track",
        "plan refresh",
    ] {
        let row = rows
            .iter()
            .find(|row| row.cli_operation == operation)
            .expect("tracked command is inventoried");
        assert_eq!(row.machine_operation, "none");
        assert_eq!(row.machine_engine_operations, "none");
    }
    rows
}
