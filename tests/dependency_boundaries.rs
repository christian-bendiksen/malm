use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::process::Command;

#[derive(Clone, Debug, Default)]
struct PackageDependencies {
    local: BTreeSet<String>,
    workspace_closure: BTreeSet<String>,
    external: BTreeSet<String>,
    external_closure: BTreeSet<String>,
    external_closure_paths: BTreeMap<String, Vec<String>>,
    declarations: BTreeMap<String, Vec<DependencyDeclaration>>,
    resolved_features: BTreeMap<String, BTreeSet<String>>,
    unclassified_paths: BTreeSet<String>,
    unapproved_sources: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DependencyDeclaration {
    kind: DependencyKind,
    version_requirement: String,
    uses_default_features: bool,
    features: BTreeSet<String>,
    optional: bool,
    target: Option<String>,
    rename: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DependencyKind {
    Normal,
    Development,
    Build,
    Unknown(String),
}

#[derive(Clone, Copy)]
struct FeaturePolicy {
    name: &'static str,
    version_requirement: Option<&'static str>,
    uses_default_features: bool,
    features: &'static [&'static str],
}

#[derive(Clone, Copy)]
struct PackageRule {
    name: &'static str,
    protected: bool,
    allowed_local: &'static [&'static str],
    allowed_workspace_closure: &'static [&'static str],
    allowed_external: &'static [&'static str],
    development_only: &'static [&'static str],
    feature_policies: &'static [FeaturePolicy],
}

#[derive(Clone, Copy)]
struct ResolvedFeaturePolicy {
    package: &'static str,
    dependency: &'static str,
    features: &'static [&'static str],
}

const RULES: &[PackageRule] = &[
    PackageRule {
        name: "malm",
        protected: true,
        allowed_local: &[
            "malm-authoring",
            "malm-config",
            "malm-engine",
            "malm-format-component-adapter",
            "malm-machine",
            "malm-module-graph",
            "malm-pack",
            "malm-root",
            "malm-tree",
            "malm-types",
        ],
        allowed_workspace_closure: &[
            "malm-archive",
            "malm-authoring",
            "malm-commit",
            "malm-config",
            "malm-engine",
            "malm-format-component-adapter",
            "malm-format-component-api",
            "malm-format-component-host",
            "malm-machine",
            "malm-module-graph",
            "malm-pack",
            "malm-root",
            "malm-store",
            "malm-tree",
            "malm-types",
        ],
        allowed_external: &[
            "anyhow",
            "clap",
            "filetime",
            "jsonschema",
            "libc",
            "pretty_assertions",
            "quote",
            "rustix",
            "serde",
            "serde_json",
            "syn",
            "tempfile",
            "xattr",
        ],
        development_only: &[
            "filetime",
            "jsonschema",
            "libc",
            "malm-config",
            "malm-module-graph",
            "malm-tree",
            "pretty_assertions",
            "quote",
            "syn",
            "tempfile",
            "xattr",
        ],
        feature_policies: &[
            FeaturePolicy {
                name: "clap",
                version_requirement: None,
                uses_default_features: true,
                features: &["derive"],
            },
            FeaturePolicy {
                name: "jsonschema",
                version_requirement: Some("=0.48.1"),
                uses_default_features: false,
                features: &[],
            },
            FeaturePolicy {
                name: "rustix",
                version_requirement: None,
                uses_default_features: true,
                features: &["fs", "process"],
            },
            FeaturePolicy {
                name: "serde",
                version_requirement: None,
                uses_default_features: true,
                features: &["derive"],
            },
            FeaturePolicy {
                name: "syn",
                version_requirement: None,
                uses_default_features: true,
                features: &["full"],
            },
        ],
    },
    PackageRule {
        name: "malm-archive",
        protected: true,
        allowed_local: &["malm-tree", "malm-types"],
        allowed_workspace_closure: &["malm-tree", "malm-types"],
        allowed_external: &["jsonschema", "serde_json", "sha2", "thiserror"],
        development_only: &["jsonschema", "serde_json"],
        feature_policies: &[FeaturePolicy {
            name: "jsonschema",
            version_requirement: Some("=0.48.1"),
            uses_default_features: false,
            features: &[],
        }],
    },
    PackageRule {
        name: "malm-authoring",
        protected: true,
        allowed_local: &["malm-config", "malm-pack", "malm-types"],
        allowed_workspace_closure: &["malm-config", "malm-pack", "malm-types"],
        allowed_external: &["kdl", "serde_json", "thiserror"],
        development_only: &[],
        feature_policies: &[FeaturePolicy {
            name: "kdl",
            version_requirement: Some("=6.5.0"),
            uses_default_features: true,
            features: &["v1"],
        }],
    },
    PackageRule {
        name: "malm-config",
        protected: true,
        allowed_local: &["malm-pack", "malm-types"],
        allowed_workspace_closure: &["malm-pack", "malm-types"],
        allowed_external: &["kdl", "serde_json", "thiserror"],
        development_only: &["serde_json"],
        feature_policies: &[FeaturePolicy {
            name: "kdl",
            version_requirement: Some("=6.5.0"),
            uses_default_features: false,
            features: &["span"],
        }],
    },
    PackageRule {
        name: "malm-commit",
        protected: true,
        allowed_local: &["malm-root", "malm-store", "malm-types"],
        allowed_workspace_closure: &["malm-root", "malm-store", "malm-types"],
        allowed_external: &[
            "rustix",
            "serde",
            "serde_json",
            "sha2",
            "tempfile",
            "thiserror",
        ],
        development_only: &["tempfile"],
        feature_policies: &[
            FeaturePolicy {
                name: "rustix",
                version_requirement: None,
                uses_default_features: true,
                features: &["fs"],
            },
            FeaturePolicy {
                name: "serde",
                version_requirement: None,
                uses_default_features: true,
                features: &["derive"],
            },
        ],
    },
    PackageRule {
        name: "malm-engine",
        protected: true,
        allowed_local: &[
            "malm-archive",
            "malm-authoring",
            "malm-config",
            "malm-commit",
            "malm-format-component-api",
            "malm-module-graph",
            "malm-pack",
            "malm-root",
            "malm-store",
            "malm-tree",
            "malm-types",
        ],
        allowed_workspace_closure: &[
            "malm-archive",
            "malm-authoring",
            "malm-config",
            "malm-commit",
            "malm-format-component-api",
            "malm-module-graph",
            "malm-pack",
            "malm-root",
            "malm-store",
            "malm-tree",
            "malm-types",
        ],
        allowed_external: &[
            "getrandom",
            "hex",
            "libc",
            "lzma-rs",
            "rustix",
            "serde",
            "serde_json",
            "tempfile",
            "thiserror",
        ],
        development_only: &["tempfile"],
        feature_policies: &[
            FeaturePolicy {
                name: "rustix",
                version_requirement: None,
                uses_default_features: true,
                features: &["fs", "process"],
            },
            FeaturePolicy {
                name: "serde",
                version_requirement: None,
                uses_default_features: true,
                features: &["derive"],
            },
        ],
    },
    PackageRule {
        name: "malm-machine",
        protected: true,
        allowed_local: &["malm-types"],
        allowed_workspace_closure: &["malm-types"],
        allowed_external: &["jsonschema", "serde", "serde_json", "thiserror"],
        development_only: &["jsonschema"],
        feature_policies: &[
            FeaturePolicy {
                name: "jsonschema",
                version_requirement: Some("=0.48.1"),
                uses_default_features: false,
                features: &[],
            },
            FeaturePolicy {
                name: "serde",
                version_requirement: None,
                uses_default_features: true,
                features: &["derive"],
            },
        ],
    },
    PackageRule {
        name: "malm-module-graph",
        protected: true,
        allowed_local: &["malm-pack", "malm-types"],
        allowed_workspace_closure: &["malm-pack", "malm-types"],
        allowed_external: &["thiserror"],
        development_only: &[],
        feature_policies: &[],
    },
    PackageRule {
        name: "malm-pack",
        protected: true,
        allowed_local: &["malm-types"],
        allowed_workspace_closure: &["malm-types"],
        allowed_external: &["kdl", "serde", "serde_json", "sha2", "thiserror", "url"],
        development_only: &[],
        feature_policies: &[
            FeaturePolicy {
                name: "kdl",
                version_requirement: Some("=6.5.0"),
                uses_default_features: false,
                features: &[],
            },
            FeaturePolicy {
                name: "serde",
                version_requirement: None,
                uses_default_features: true,
                features: &["derive"],
            },
            FeaturePolicy {
                name: "url",
                version_requirement: Some("=2.5.8"),
                uses_default_features: true,
                features: &[],
            },
        ],
    },
    PackageRule {
        name: "malm-format-component-api",
        protected: true,
        allowed_local: &["malm-types"],
        allowed_workspace_closure: &["malm-types"],
        allowed_external: &["serde", "wit-parser"],
        development_only: &["wit-parser"],
        feature_policies: &[
            FeaturePolicy {
                name: "serde",
                version_requirement: None,
                uses_default_features: true,
                features: &["derive"],
            },
            FeaturePolicy {
                name: "wit-parser",
                version_requirement: Some("=0.236.1"),
                uses_default_features: false,
                features: &[],
            },
        ],
    },
    PackageRule {
        name: "malm-format-component-adapter",
        protected: true,
        allowed_local: &[
            "malm-config",
            "malm-engine",
            "malm-format-component-api",
            "malm-format-component-host",
            "malm-types",
        ],
        allowed_workspace_closure: &[
            "malm-archive",
            "malm-authoring",
            "malm-commit",
            "malm-config",
            "malm-engine",
            "malm-format-component-api",
            "malm-format-component-host",
            "malm-module-graph",
            "malm-pack",
            "malm-root",
            "malm-store",
            "malm-tree",
            "malm-types",
        ],
        allowed_external: &[],
        development_only: &[],
        feature_policies: &[],
    },
    PackageRule {
        name: "malm-format-component-host",
        protected: true,
        allowed_local: &["malm-config", "malm-format-component-api", "malm-types"],
        allowed_workspace_closure: &[
            "malm-config",
            "malm-format-component-api",
            "malm-pack",
            "malm-types",
        ],
        allowed_external: &[
            "thiserror",
            "wasmparser",
            "wasmtime",
            "wat",
            "wit-component",
            "wit-parser",
        ],
        development_only: &["wat", "wit-component", "wit-parser"],
        feature_policies: &[
            FeaturePolicy {
                name: "wasmparser",
                version_requirement: Some("=0.236.1"),
                uses_default_features: false,
                features: &["component-model", "features", "simd", "std", "validate"],
            },
            FeaturePolicy {
                name: "wasmtime",
                version_requirement: Some("=36.0.12"),
                uses_default_features: false,
                features: &["cache", "component-model", "cranelift", "runtime", "std"],
            },
            FeaturePolicy {
                name: "wat",
                version_requirement: Some("=1.236.1"),
                uses_default_features: false,
                features: &["component-model"],
            },
            FeaturePolicy {
                name: "wit-component",
                version_requirement: Some("=0.236.1"),
                uses_default_features: false,
                features: &["dummy-module"],
            },
            FeaturePolicy {
                name: "wit-parser",
                version_requirement: Some("=0.236.1"),
                uses_default_features: false,
                features: &[],
            },
        ],
    },
    PackageRule {
        name: "malm-root",
        protected: true,
        allowed_local: &[],
        allowed_workspace_closure: &[],
        allowed_external: &["serde", "serde_json", "thiserror"],
        development_only: &[],
        feature_policies: &[FeaturePolicy {
            name: "serde",
            version_requirement: None,
            uses_default_features: true,
            features: &["derive"],
        }],
    },
    PackageRule {
        name: "malm-store",
        protected: true,
        allowed_local: &["malm-types"],
        allowed_workspace_closure: &["malm-types"],
        allowed_external: &["serde", "serde_json", "thiserror"],
        development_only: &[],
        feature_policies: &[FeaturePolicy {
            name: "serde",
            version_requirement: None,
            uses_default_features: true,
            features: &["derive"],
        }],
    },
    PackageRule {
        name: "malm-tree",
        protected: true,
        allowed_local: &["malm-types"],
        allowed_workspace_closure: &["malm-types"],
        allowed_external: &["thiserror"],
        development_only: &[],
        feature_policies: &[],
    },
    PackageRule {
        name: "malm-types",
        protected: true,
        allowed_local: &[],
        allowed_workspace_closure: &[],
        allowed_external: &["serde", "sha2", "thiserror"],
        development_only: &[],
        feature_policies: &[FeaturePolicy {
            name: "serde",
            version_requirement: None,
            uses_default_features: true,
            features: &["derive"],
        }],
    },
];
const RESOLVED_FEATURE_POLICIES: &[ResolvedFeaturePolicy] = &[
    ResolvedFeaturePolicy {
        package: "malm-format-component-host",
        dependency: "wasmparser",
        features: &[
            "component-model",
            "features",
            "hash-collections",
            "serde",
            "simd",
            "std",
            "validate",
        ],
    },
    ResolvedFeaturePolicy {
        package: "malm-format-component-host",
        dependency: "wasmtime",
        features: &[
            "cache",
            "component-model",
            "cranelift",
            "once_cell",
            "runtime",
            "std",
            "wasmtime-jit-icache-coherence",
        ],
    },
    ResolvedFeaturePolicy {
        package: "malm-format-component-host",
        dependency: "wat",
        features: &["component-model"],
    },
];
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[test]
fn workspace_dependencies_respect_architecture() {
    let graph = workspace_graph();
    validate_policy(&graph)
        .unwrap_or_else(|error| panic!("dependency boundary violation: {error}"));
}

#[test]
fn engine_host_effects_are_confined_to_explicit_adapters() {
    let source_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/malm-engine/src");
    let files = rust_sources(&source_root);
    for (pattern, allowed) in [
        ("rustix::process::geteuid", &["ports.rs"][..]),
        ("getrlimit(Resource::Nofile)", &["ports.rs"][..]),
        ("getrandom::fill", &["ports.rs"][..]),
        ("Command::new", &["git_acquisition/process.rs"][..]),
    ] {
        let mut violations = Vec::new();
        for path in &files {
            let source = std::fs::read_to_string(source_root.join(path)).unwrap();
            if source.contains(pattern) && !allowed.contains(&path.as_str()) {
                violations.push(path.clone());
            }
        }
        assert!(
            violations.is_empty(),
            "host effect {pattern:?} escaped its explicit adapter: {violations:?}"
        );
    }

    for forbidden in ["std::net::", "rustix::net::", "libc::socket"] {
        let violations: Vec<_> = files
            .iter()
            .filter(|path| {
                std::fs::read_to_string(source_root.join(path))
                    .unwrap()
                    .contains(forbidden)
            })
            .cloned()
            .collect();
        assert!(
            violations.is_empty(),
            "direct network effect {forbidden:?} exists below Engine ports: {violations:?}"
        );
    }
}

#[test]
fn machine_contract_has_no_host_effects() {
    let source_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/malm-machine/src");
    let files = rust_sources(&source_root);
    for forbidden in [
        "std::env::",
        "std::fs::",
        "std::net::",
        "std::process::",
        "std::thread::",
        "std::time::",
        "rustix::",
        "libc::",
        "Command::new",
    ] {
        let violations: Vec<_> = files
            .iter()
            .filter(|path| {
                std::fs::read_to_string(source_root.join(path))
                    .unwrap()
                    .contains(forbidden)
            })
            .cloned()
            .collect();
        assert!(
            violations.is_empty(),
            "host effect {forbidden:?} exists in pure machine contract sources: {violations:?}"
        );
    }
}

#[test]
fn tree_contract_is_pure_and_capability_free() {
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/malm-tree/src");
    let files = rust_sources(&source_root);
    for forbidden in [
        "std::env::",
        "std::fs::",
        "std::net::",
        "std::process::",
        "std::thread::",
        "rustix::",
        "libc::",
        "Command::new",
        "malm_format_component",
        "unsafe {",
        "unsafe fn",
        "unsafe impl",
    ] {
        let violations: Vec<_> = files
            .iter()
            .filter(|path| {
                std::fs::read_to_string(source_root.join(path))
                    .unwrap()
                    .contains(forbidden)
            })
            .cloned()
            .collect();
        assert!(
            violations.is_empty(),
            "forbidden capability {forbidden:?} exists in pure tree sources: {violations:?}"
        );
    }
}

#[test]
fn commit_package_is_offline_and_prepare_free() {
    let graph = workspace_graph();
    let forbidden = BTreeSet::from([
        "malm-config".to_owned(),
        "malm-format-component-adapter".to_owned(),
        "malm-format-component-api".to_owned(),
        "malm-format-component-host".to_owned(),
        "malm-module-graph".to_owned(),
        "malm-pack".to_owned(),
    ]);
    assert_eq!(find_forbidden_path(&graph, "malm-commit", &forbidden), None);
    assert!(
        graph["malm-commit"]
            .external_closure
            .iter()
            .all(|dependency| !is_component_runtime_package(dependency))
    );

    let source_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/malm-commit/src");
    let files = rust_sources(&source_root);
    for forbidden in [
        "std::net",
        "rustix::net",
        "std::process",
        "Command::new",
        "malm_config",
        "malm_module_graph",
        "malm_pack",
        "malm_format_component",
    ] {
        let violations: Vec<_> = files
            .iter()
            .filter(|path| {
                if path.as_str() == "failpoint.rs" {
                    return false;
                }
                std::fs::read_to_string(source_root.join(path))
                    .unwrap()
                    .contains(forbidden)
            })
            .cloned()
            .collect();
        assert!(
            violations.is_empty(),
            "commit-only source contains forbidden capability {forbidden:?}: {violations:?}"
        );
    }
}

#[test]
fn format_component_host_has_no_ambient_capability_or_runtime_escape_surface() {
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/malm-format-component-host/src");
    let files = rust_sources(&source_root);
    for forbidden in [
        "std::env::",
        "std::fs::",
        "std::net::",
        "std::process::",
        "std::thread",
        "std::time",
        "Command::new",
        "wasmtime_wasi",
        "pub use wasmtime",
        "pub use wasmparser",
        "pub fn engine(",
        "pub fn component(",
    ] {
        let violations: Vec<_> = files
            .iter()
            .filter(|path| {
                if path.as_str() == "watchdog.rs"
                    && matches!(forbidden, "std::thread" | "std::time")
                    || path.as_str() == "tests.rs"
                        && matches!(forbidden, "std::thread" | "std::time")
                {
                    return false;
                }
                std::fs::read_to_string(source_root.join(path))
                    .unwrap()
                    .contains(forbidden)
            })
            .cloned()
            .collect();
        assert!(
            violations.is_empty(),
            "ambient capability or runtime escape surface {forbidden:?} exists in format-component host sources: {violations:?}"
        );
    }
}

#[test]
fn format_component_host_public_api_is_exact_and_runtime_opaque() {
    use quote::ToTokens;

    let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/malm-format-component-host/src/lib.rs");
    let source = std::fs::read_to_string(source_path).unwrap();
    let file = syn::parse_file(&source).expect("parse format-component host source");
    let mut public_items = BTreeSet::new();
    let mut public_signatures = BTreeSet::new();
    let mut error_variants = BTreeSet::new();

    for item in &file.items {
        match item {
            syn::Item::Const(item) if is_public(&item.vis) => {
                public_items.insert(format!("const {}", item.ident));
            }
            syn::Item::Enum(item) if is_public(&item.vis) => {
                public_items.insert(format!("enum {}", item.ident));
                if item.ident == "ComponentAdmissionError" {
                    error_variants.extend(
                        item.variants
                            .iter()
                            .map(|variant| variant.ident.to_string()),
                    );
                }
            }
            syn::Item::Struct(item) if is_public(&item.vis) => {
                public_items.insert(format!("struct {}", item.ident));
                assert!(
                    item.fields.iter().all(|field| !is_public(&field.vis)),
                    "format-component host public structs must not expose runtime-bearing fields"
                );
            }
            syn::Item::Impl(item) => {
                let self_shape = item.self_ty.to_token_stream().to_string();
                let self_type = match item.self_ty.as_ref() {
                    syn::Type::Path(path) => {
                        path.path.segments.last().map(|part| part.ident.to_string())
                    }
                    _ => None,
                };
                if let Some((_, trait_path, _)) = &item.trait_
                    && [
                        "FormatComponentHost",
                        "AdmittedFormatComponent",
                        "HostInitializationError",
                        "ComponentAdmissionError",
                        "FormatComponentInvocationError",
                    ]
                    .iter()
                    .any(|wrapper| self_shape.contains(wrapper))
                {
                    let trait_shape = trait_path.to_token_stream().to_string();
                    let allowed = matches!(
                        (self_shape.as_str(), trait_shape.as_str()),
                        ("FormatComponentHost", "fmt :: Debug")
                            | ("AdmittedFormatComponent", "fmt :: Debug")
                            | ("HostInitializationError", "fmt :: Display")
                            | ("HostInitializationError", "std :: error :: Error")
                            | ("ComponentAdmissionError", "fmt :: Display")
                            | ("ComponentAdmissionError", "std :: error :: Error")
                            | ("FormatComponentInvocationError", "fmt :: Display")
                            | ("FormatComponentInvocationError", "std :: error :: Error")
                    );
                    assert!(
                        allowed,
                        "unreviewed public wrapper trait implementation {trait_shape} for {self_shape}"
                    );
                }
                if item.trait_.is_none()
                    && let Some(self_type) = self_type
                {
                    for item in &item.items {
                        match item {
                            syn::ImplItem::Fn(method) if is_public(&method.vis) => {
                                public_signatures.insert(format!(
                                    "{self_type}::{}",
                                    method.sig.to_token_stream()
                                ));
                            }
                            syn::ImplItem::Const(item) if is_public(&item.vis) => {
                                public_signatures
                                    .insert(format!("{self_type}::const {}", item.ident));
                            }
                            syn::ImplItem::Type(item) if is_public(&item.vis) => {
                                public_signatures
                                    .insert(format!("{self_type}::type {}", item.ident));
                            }
                            syn::ImplItem::Macro(_) => {
                                panic!("macros cannot generate format-component host inherent API");
                            }
                            _ => {}
                        }
                    }
                }
            }
            syn::Item::Fn(item) if is_public(&item.vis) => {
                public_items.insert(format!("fn {}", item.sig.ident));
            }
            syn::Item::Type(item) => {
                public_items.insert(format!("type alias {}", item.ident));
            }
            syn::Item::Use(item) if is_public(&item.vis) => {
                public_items.insert("public use".to_owned());
            }
            syn::Item::ExternCrate(item) if is_public(&item.vis) => {
                public_items.insert(format!("extern crate {}", item.ident));
            }
            syn::Item::ForeignMod(_) => {
                public_items.insert("extern block".to_owned());
            }
            syn::Item::Mod(item)
                if !["bindings", "conversion", "runtime", "watchdog"]
                    .contains(&item.ident.to_string().as_str())
                    && (item.ident != "tests"
                        || !item
                            .attrs
                            .iter()
                            .any(|attribute| attribute.path().is_ident("cfg"))) =>
            {
                public_items.insert(format!("mod {}", item.ident));
            }
            syn::Item::Static(item) if is_public(&item.vis) => {
                public_items.insert(format!("static {}", item.ident));
            }
            syn::Item::Trait(item) if is_public(&item.vis) => {
                public_items.insert(format!("trait {}", item.ident));
            }
            syn::Item::TraitAlias(item) if is_public(&item.vis) => {
                public_items.insert(format!("trait alias {}", item.ident));
            }
            syn::Item::Union(item) if is_public(&item.vis) => {
                public_items.insert(format!("union {}", item.ident));
            }
            syn::Item::Macro(_) => {
                public_items.insert("source macro".to_owned());
            }
            _ => {}
        }
    }

    assert_eq!(
        public_items,
        BTreeSet::from([
            "const COMPONENT_PROFILE_V1".to_owned(),
            "const EXECUTION_PROFILE_V1".to_owned(),
            "const MAX_COMPONENT_BYTES".to_owned(),
            "enum ComponentAdmissionError".to_owned(),
            "enum GuestTrapCodeV1".to_owned(),
            "enum FormatComponentInvocationError".to_owned(),
            "fn execution_profile_digest_v1".to_owned(),
            "struct AdmittedFormatComponent".to_owned(),
            "struct FormatComponentHost".to_owned(),
            "struct HostInitializationError".to_owned(),
        ])
    );
    assert_eq!(
        public_signatures,
        BTreeSet::from([
            "AdmittedFormatComponent::const fn byte_len (& self) -> usize".to_owned(),
            "AdmittedFormatComponent::const fn component_profile (& self) -> & 'static str".to_owned(),
            "AdmittedFormatComponent::const fn digest (& self) -> & Digest".to_owned(),
            "AdmittedFormatComponent::const fn execution_profile_digest (& self) -> & Digest".to_owned(),
            "AdmittedFormatComponent::fn transform (& self , request : & config_api :: TransformRequestV1 ,) -> Result < Result < config_api :: TransformResponseV1 , config_api :: TransformFailureV1 > , FormatComponentInvocationError , >".to_owned(),
            "FormatComponentHost::const fn execution_profile_digest (& self) -> & Digest".to_owned(),
            "FormatComponentHost::fn admit_component (& self , authorization : & component_api :: FormatComponentAuthorizationV1 , expected_digest : & Digest , bytes : & [u8] ,) -> Result < AdmittedFormatComponent , ComponentAdmissionError >".to_owned(),
            "FormatComponentHost::fn new () -> Result < Self , HostInitializationError >".to_owned(),
            "FormatComponentHost::fn with_compile_cache (cache_dir : & std :: path :: Path ,) -> Result < Self , HostInitializationError >".to_owned(),
            "HostInitializationError::fn reason (& self) -> & str".to_owned(),
        ])
    );
    assert_eq!(
        error_variants,
        BTreeSet::from([
            "CompilationFailed".to_owned(),
            "CoreModule".to_owned(),
            "DigestMismatch".to_owned(),
            "ImportsNotAllowed".to_owned(),
            "InputTooLarge".to_owned(),
            "InterfaceMismatch".to_owned(),
            "InvalidComponent".to_owned(),
            "UnauthorizedDigest".to_owned(),
        ])
    );
}

#[test]
fn format_component_execution_profile_matches_runtime_dependency_declarations() {
    let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/malm-format-component-host/src/lib.rs");
    let source = std::fs::read_to_string(source_path).unwrap();
    let file = syn::parse_file(&source).expect("parse format-component host source");
    let string_constants: BTreeMap<_, _> = file
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Const(item) = item else {
                return None;
            };
            let syn::Expr::Lit(expression) = item.expr.as_ref() else {
                return None;
            };
            let syn::Lit::Str(value) = &expression.lit else {
                return None;
            };
            Some((item.ident.to_string(), value.value()))
        })
        .collect();

    let graph = workspace_graph();
    let host = graph.get("malm-format-component-host").unwrap();
    for (dependency, version_constant, features_constant) in [
        ("wasmtime", "WASMTIME_VERSION", Some("WASMTIME_FEATURES")),
        ("wasmparser", "WASMPARSER_VERSION", None),
    ] {
        let declaration = host
            .declarations
            .get(dependency)
            .unwrap()
            .iter()
            .find(|declaration| declaration.kind == DependencyKind::Normal)
            .unwrap();
        assert_eq!(
            declaration.version_requirement,
            format!("={}", string_constants[version_constant])
        );
        if let Some(features_constant) = features_constant {
            // Wasmtime's `cache` feature only reuses serialized machine code
            // across processes. It cannot change component results and is
            // therefore excluded from the execution profile identity.
            assert_eq!(
                declaration
                    .features
                    .iter()
                    .filter(|feature| feature.as_str() != "cache")
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
                string_constants[features_constant]
            );
        }
    }
}

fn is_public(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}

#[test]
fn forbidden_path_detection_covers_direct_and_transitive_edges() {
    let graph = BTreeMap::from([
        ("engine".to_owned(), dependencies(&["core", "cli"])),
        ("core".to_owned(), dependencies(&["adapter"])),
        ("adapter".to_owned(), dependencies(&[])),
        ("cli".to_owned(), dependencies(&[])),
    ]);
    let forbidden = BTreeSet::from(["adapter".to_owned(), "cli".to_owned()]);

    assert_eq!(
        find_forbidden_path(&graph, "engine", &forbidden),
        Some(vec!["engine".to_owned(), "cli".to_owned()])
    );

    let graph = BTreeMap::from([
        ("engine".to_owned(), dependencies(&["core"])),
        ("core".to_owned(), dependencies(&["adapter"])),
        ("adapter".to_owned(), dependencies(&[])),
    ]);
    assert_eq!(
        find_forbidden_path(&graph, "engine", &forbidden),
        Some(vec![
            "engine".to_owned(),
            "core".to_owned(),
            "adapter".to_owned()
        ])
    );
}

#[test]
fn dependency_classification_binds_package_identity_and_source() {
    let workspace_members = BTreeSet::from(["workspace malm-types"]);
    let mut dependencies = PackageDependencies::default();
    let path_impostor = serde_json::json!({
        "name": "malm-types",
        "manifest_path": "/outside/malm-types/Cargo.toml",
        "source": null
    });
    classify_resolved_dependency(
        &mut dependencies,
        &workspace_members,
        "outside malm-types",
        &path_impostor,
    );
    assert!(dependencies.local.is_empty());
    assert_eq!(
        dependencies.unclassified_paths,
        BTreeSet::from(["malm-types (/outside/malm-types/Cargo.toml)".to_owned()])
    );

    let alternate_registry = serde_json::json!({
        "name": "serde",
        "manifest_path": "/registry/serde/Cargo.toml",
        "source": "registry+https://packages.example.invalid/index"
    });
    classify_resolved_dependency(
        &mut dependencies,
        &workspace_members,
        "alternate serde",
        &alternate_registry,
    );
    assert!(dependencies.external.is_empty());
    assert_eq!(
        dependencies.unapproved_sources,
        BTreeSet::from(["serde (registry+https://packages.example.invalid/index)".to_owned()])
    );
}

#[test]
fn dependency_source_validation_covers_transitive_replacements() {
    let packages = serde_json::json!([
        {
            "id": "workspace engine",
            "name": "malm-engine",
            "manifest_path": "/workspace/engine/Cargo.toml",
            "source": null
        },
        {
            "id": "registry serde",
            "name": "serde",
            "manifest_path": "/registry/serde/Cargo.toml",
            "source": CRATES_IO_SOURCE
        },
        {
            "id": "patched derive",
            "name": "serde_derive",
            "manifest_path": "/outside/serde_derive/Cargo.toml",
            "source": null
        }
    ]);
    let nodes = serde_json::json!([
        {"id": "workspace engine", "deps": [{"pkg": "registry serde"}]},
        {"id": "registry serde", "deps": [{"pkg": "patched derive"}]},
        {"id": "patched derive", "deps": []}
    ]);
    let packages_by_id: BTreeMap<&str, &serde_json::Value> = packages
        .as_array()
        .unwrap()
        .iter()
        .map(|package| (package["id"].as_str().unwrap(), package))
        .collect();
    let nodes_by_id: BTreeMap<&str, &serde_json::Value> = nodes
        .as_array()
        .unwrap()
        .iter()
        .map(|node| (node["id"].as_str().unwrap(), node))
        .collect();
    let workspace_members = BTreeSet::from(["workspace engine"]);
    let mut dependencies = PackageDependencies::default();

    classify_resolved_closure(
        &mut dependencies,
        "workspace engine",
        &workspace_members,
        &packages_by_id,
        &nodes_by_id,
    );

    assert_eq!(
        dependencies.unclassified_paths,
        BTreeSet::from([
            "malm-engine -> serde -> serde_derive (/outside/serde_derive/Cargo.toml)".to_owned()
        ])
    );
}

#[test]
fn workspace_closure_classification_includes_transitive_packages() {
    let packages = serde_json::json!([
        {
            "id": "workspace engine",
            "name": "engine",
            "manifest_path": "/workspace/engine/Cargo.toml",
            "source": null
        },
        {
            "id": "workspace core",
            "name": "core",
            "manifest_path": "/workspace/core/Cargo.toml",
            "source": null
        },
        {
            "id": "workspace types",
            "name": "types",
            "manifest_path": "/workspace/types/Cargo.toml",
            "source": null
        }
    ]);
    let nodes = serde_json::json!([
        {"id": "workspace engine", "deps": [{"pkg": "workspace core"}]},
        {"id": "workspace core", "deps": [{"pkg": "workspace types"}]},
        {"id": "workspace types", "deps": []}
    ]);
    let packages_by_id: BTreeMap<&str, &serde_json::Value> = packages
        .as_array()
        .unwrap()
        .iter()
        .map(|package| (package["id"].as_str().unwrap(), package))
        .collect();
    let nodes_by_id: BTreeMap<&str, &serde_json::Value> = nodes
        .as_array()
        .unwrap()
        .iter()
        .map(|node| (node["id"].as_str().unwrap(), node))
        .collect();
    let workspace_members =
        BTreeSet::from(["workspace engine", "workspace core", "workspace types"]);
    let mut dependencies = PackageDependencies::default();

    classify_resolved_closure(
        &mut dependencies,
        "workspace engine",
        &workspace_members,
        &packages_by_id,
        &nodes_by_id,
    );

    assert_eq!(
        dependencies.workspace_closure,
        BTreeSet::from(["core".to_owned(), "types".to_owned()])
    );
}

#[test]
fn dependency_declaration_policy_freezes_kind_and_features() {
    let rule = PackageRule {
        name: "protected",
        protected: true,
        allowed_local: &[],
        allowed_workspace_closure: &[],
        allowed_external: &["serde", "test-only"],
        development_only: &["test-only"],
        feature_policies: &[FeaturePolicy {
            name: "serde",
            version_requirement: Some("^1"),
            uses_default_features: true,
            features: &["derive"],
        }],
    };
    let declarations = BTreeMap::from([
        (
            "serde".to_owned(),
            vec![DependencyDeclaration {
                kind: DependencyKind::Normal,
                version_requirement: "^1".to_owned(),
                uses_default_features: true,
                features: BTreeSet::from(["derive".to_owned()]),
                optional: false,
                target: None,
                rename: None,
            }],
        ),
        (
            "test-only".to_owned(),
            vec![DependencyDeclaration {
                kind: DependencyKind::Development,
                version_requirement: "^1".to_owned(),
                uses_default_features: true,
                features: BTreeSet::new(),
                optional: false,
                target: None,
                rename: None,
            }],
        ),
    ]);
    validate_dependency_declarations(&rule, &declarations).unwrap();

    let mut promoted = declarations.clone();
    promoted.get_mut("test-only").unwrap().clear();
    promoted
        .get_mut("test-only")
        .unwrap()
        .push(DependencyDeclaration {
            kind: DependencyKind::Normal,
            version_requirement: "^1".to_owned(),
            uses_default_features: true,
            features: BTreeSet::new(),
            optional: false,
            target: None,
            rename: None,
        });
    assert!(validate_dependency_declarations(&rule, &promoted).is_err());

    let mut relaxed = declarations.clone();
    relaxed.get_mut("serde").unwrap()[0].version_requirement = ">=1".to_owned();
    assert!(validate_dependency_declarations(&rule, &relaxed).is_err());

    let mut widened = declarations;
    widened.get_mut("serde").unwrap().clear();
    widened
        .get_mut("serde")
        .unwrap()
        .push(DependencyDeclaration {
            kind: DependencyKind::Normal,
            version_requirement: "^1".to_owned(),
            uses_default_features: true,
            features: BTreeSet::from(["derive".to_owned(), "rc".to_owned()]),
            optional: false,
            target: None,
            rename: None,
        });
    assert!(validate_dependency_declarations(&rule, &widened).is_err());
}

fn workspace_graph() -> BTreeMap<String, PackageDependencies> {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--locked",
            "--all-features",
            "--format-version",
            "1",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse cargo metadata");
    let workspace_members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .expect("workspace_members array")
        .iter()
        .map(|member| member.as_str().expect("workspace member package ID"))
        .collect();
    let packages = metadata["packages"].as_array().expect("packages array");
    let packages_by_id: BTreeMap<&str, &serde_json::Value> = packages
        .iter()
        .map(|package| (package["id"].as_str().expect("package ID"), package))
        .collect();
    let nodes_by_id: BTreeMap<&str, &serde_json::Value> = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolved dependency nodes")
        .iter()
        .map(|node| (node["id"].as_str().expect("resolved package ID"), node))
        .collect();

    workspace_members
        .iter()
        .map(|package_id| {
            let package = packages_by_id
                .get(package_id)
                .copied()
                .expect("workspace package details");
            let name = package["name"].as_str().expect("package name").to_owned();
            let mut dependencies = PackageDependencies::default();
            classify_dependency_declarations(&mut dependencies, package);
            let node = nodes_by_id
                .get(package_id)
                .copied()
                .expect("workspace dependency node");
            for dependency in node["deps"]
                .as_array()
                .expect("resolved package dependencies")
            {
                let dependency_id = dependency["pkg"]
                    .as_str()
                    .expect("resolved dependency package ID");
                let dependency_package = packages_by_id
                    .get(dependency_id)
                    .copied()
                    .expect("resolved dependency package details");
                record_resolved_features(
                    &mut dependencies,
                    dependency_id,
                    dependency_package,
                    &nodes_by_id,
                );
                classify_resolved_dependency(
                    &mut dependencies,
                    &workspace_members,
                    dependency_id,
                    dependency_package,
                );
            }
            classify_resolved_closure(
                &mut dependencies,
                package_id,
                &workspace_members,
                &packages_by_id,
                &nodes_by_id,
            );
            (name, dependencies)
        })
        .collect()
}

fn record_resolved_features(
    dependencies: &mut PackageDependencies,
    dependency_id: &str,
    package: &serde_json::Value,
    nodes_by_id: &BTreeMap<&str, &serde_json::Value>,
) {
    let name = package["name"].as_str().expect("dependency package name");
    let node = nodes_by_id
        .get(dependency_id)
        .copied()
        .expect("resolved dependency node");
    dependencies
        .resolved_features
        .entry(name.to_owned())
        .or_default()
        .extend(
            node["features"]
                .as_array()
                .expect("resolved dependency features")
                .iter()
                .map(|feature| {
                    feature
                        .as_str()
                        .expect("resolved dependency feature")
                        .to_owned()
                }),
        );
}

fn classify_dependency_declarations(
    dependencies: &mut PackageDependencies,
    package: &serde_json::Value,
) {
    for declaration in package["dependencies"]
        .as_array()
        .expect("declared package dependencies")
    {
        let name = declaration["name"]
            .as_str()
            .expect("declared dependency name");
        let kind = match declaration["kind"].as_str() {
            None => DependencyKind::Normal,
            Some("dev") => DependencyKind::Development,
            Some("build") => DependencyKind::Build,
            Some(kind) => DependencyKind::Unknown(kind.to_owned()),
        };
        let features = declaration["features"]
            .as_array()
            .expect("declared dependency features")
            .iter()
            .map(|feature| {
                feature
                    .as_str()
                    .expect("declared dependency feature")
                    .to_owned()
            })
            .collect();
        dependencies
            .declarations
            .entry(name.to_owned())
            .or_default()
            .push(DependencyDeclaration {
                kind,
                version_requirement: declaration["req"]
                    .as_str()
                    .expect("declared dependency version requirement")
                    .to_owned(),
                uses_default_features: declaration["uses_default_features"]
                    .as_bool()
                    .expect("declared default-feature setting"),
                features,
                optional: declaration["optional"]
                    .as_bool()
                    .expect("declared optional setting"),
                target: declaration["target"].as_str().map(str::to_owned),
                rename: declaration["rename"].as_str().map(str::to_owned),
            });
    }
}

fn classify_resolved_closure<'a>(
    dependencies: &mut PackageDependencies,
    start_id: &'a str,
    workspace_members: &BTreeSet<&'a str>,
    packages_by_id: &BTreeMap<&'a str, &'a serde_json::Value>,
    nodes_by_id: &BTreeMap<&'a str, &'a serde_json::Value>,
) {
    let start = packages_by_id[start_id]["name"]
        .as_str()
        .expect("protected package name");
    let mut queue = VecDeque::from([(start_id, vec![start.to_owned()])]);
    let mut visited = BTreeSet::new();
    while let Some((package_id, path)) = queue.pop_front() {
        if !visited.insert(package_id) {
            continue;
        }
        let node = nodes_by_id
            .get(package_id)
            .copied()
            .expect("resolved closure node");
        for dependency in node["deps"]
            .as_array()
            .expect("resolved closure dependencies")
        {
            if package_id != start_id && dependency_is_development_only(dependency) {
                continue;
            }
            let dependency_id = dependency["pkg"]
                .as_str()
                .expect("resolved closure package ID");
            let package = packages_by_id
                .get(dependency_id)
                .copied()
                .expect("resolved closure package details");
            let name = package["name"]
                .as_str()
                .expect("resolved closure package name");
            let mut dependency_path = path.clone();
            dependency_path.push(name.to_owned());
            if workspace_members.contains(dependency_id) {
                dependencies.workspace_closure.insert(name.to_owned());
            } else {
                match package["source"].as_str() {
                    Some(CRATES_IO_SOURCE) => {
                        dependencies.external_closure.insert(name.to_owned());
                        dependencies
                            .external_closure_paths
                            .entry(name.to_owned())
                            .or_insert(dependency_path.clone());
                    }
                    Some(source) => {
                        dependencies
                            .unapproved_sources
                            .insert(format!("{} ({source})", dependency_path.join(" -> ")));
                    }
                    None => {
                        let manifest = package["manifest_path"]
                            .as_str()
                            .expect("resolved path manifest");
                        dependencies
                            .unclassified_paths
                            .insert(format!("{} ({manifest})", dependency_path.join(" -> ")));
                    }
                }
            }
            queue.push_back((dependency_id, dependency_path));
        }
    }
}

fn dependency_is_development_only(dependency: &serde_json::Value) -> bool {
    let Some(kinds) = dependency["dep_kinds"].as_array() else {
        return false;
    };
    !kinds.is_empty()
        && kinds
            .iter()
            .all(|kind| kind["kind"].as_str() == Some("dev"))
}

fn classify_resolved_dependency(
    dependencies: &mut PackageDependencies,
    workspace_members: &BTreeSet<&str>,
    dependency_id: &str,
    package: &serde_json::Value,
) {
    let name = package["name"].as_str().expect("dependency package name");
    if workspace_members.contains(dependency_id) {
        dependencies.local.insert(name.to_owned());
        return;
    }

    match package["source"].as_str() {
        Some(CRATES_IO_SOURCE) => {
            dependencies.external.insert(name.to_owned());
        }
        Some(source) => {
            dependencies
                .unapproved_sources
                .insert(format!("{name} ({source})"));
        }
        None => {
            let manifest = package["manifest_path"]
                .as_str()
                .expect("path dependency manifest");
            dependencies
                .unclassified_paths
                .insert(format!("{name} ({manifest})"));
        }
    }
}

fn validate_policy(graph: &BTreeMap<String, PackageDependencies>) -> Result<(), String> {
    let expected_packages: BTreeSet<&str> = RULES.iter().map(|rule| rule.name).collect();
    let actual_packages: BTreeSet<&str> = graph.keys().map(String::as_str).collect();
    if actual_packages != expected_packages {
        let unclassified: Vec<_> = actual_packages
            .difference(&expected_packages)
            .copied()
            .collect();
        let missing: Vec<_> = expected_packages
            .difference(&actual_packages)
            .copied()
            .collect();
        return Err(format!(
            "workspace package classification is incomplete; unclassified={unclassified:?}, missing={missing:?}"
        ));
    }

    for (name, dependencies) in graph {
        if !dependencies.unclassified_paths.is_empty() {
            return Err(format!(
                "{name} has path dependencies outside the classified workspace: {:?}",
                dependencies.unclassified_paths
            ));
        }
        if !dependencies.unapproved_sources.is_empty() {
            return Err(format!(
                "{name} has dependencies from unapproved package sources: {:?}",
                dependencies.unapproved_sources
            ));
        }
    }

    for rule in RULES.iter().filter(|rule| rule.protected) {
        let dependencies = &graph[rule.name];
        reject_unapproved(
            rule.name,
            "workspace",
            &dependencies.local,
            rule.allowed_local,
        )?;
        reject_unapproved(
            rule.name,
            "transitive workspace",
            &dependencies.workspace_closure,
            rule.allowed_workspace_closure,
        )?;
        reject_unapproved(
            rule.name,
            "external",
            &dependencies.external,
            rule.allowed_external,
        )?;
        validate_dependency_declarations(rule, &dependencies.declarations)?;
    }

    validate_resolved_feature_policies(graph)?;

    let component_runtime = BTreeSet::from(["malm-format-component-host".to_owned()]);
    for package in ["malm-commit", "malm-engine", "malm-machine"] {
        if let Some(path) = find_forbidden_path(graph, package, &component_runtime) {
            return Err(format!(
                "{package} reaches the prepare-only format-component runtime: {}",
                path.join(" -> ")
            ));
        }
    }
    let forbidden: BTreeSet<String> = RULES
        .iter()
        .filter(|rule| !rule.protected)
        .map(|rule| rule.name.to_owned())
        .collect();
    for rule in RULES.iter().filter(|rule| rule.protected) {
        if let Some(path) = find_forbidden_path(graph, rule.name, &forbidden) {
            return Err(format!(
                "{} reaches an unprotected outer effect layer: {}",
                rule.name,
                path.join(" -> ")
            ));
        }
    }

    Ok(())
}

fn is_component_runtime_package(name: &str) -> bool {
    name == "wasm3"
        || name == "wasmi"
        || name == "wasmer"
        || name.starts_with("wasmer-")
        || name == "wasmtime"
        || name.starts_with("wasmtime-")
}

fn validate_resolved_feature_policies(
    graph: &BTreeMap<String, PackageDependencies>,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for policy in RESOLVED_FEATURE_POLICIES {
        if !seen.insert((policy.package, policy.dependency)) {
            return Err(format!(
                "resolved feature policy repeats {} -> {}",
                policy.package, policy.dependency
            ));
        }
        let package = graph.get(policy.package).ok_or_else(|| {
            format!(
                "resolved feature policy names unknown package {}",
                policy.package
            )
        })?;
        let actual = package
            .resolved_features
            .get(policy.dependency)
            .ok_or_else(|| {
                format!(
                    "resolved feature policy names undeclared dependency {} -> {}",
                    policy.package, policy.dependency
                )
            })?;
        let expected: BTreeSet<String> = policy
            .features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect();
        if actual != &expected {
            return Err(format!(
                "{} dependency {} resolved features differ from policy: actual={actual:?}, expected={expected:?}",
                policy.package, policy.dependency
            ));
        }
    }
    Ok(())
}

fn validate_dependency_declarations(
    rule: &PackageRule,
    actual: &BTreeMap<String, Vec<DependencyDeclaration>>,
) -> Result<(), String> {
    let expected_names: BTreeSet<&str> = rule
        .allowed_local
        .iter()
        .chain(rule.allowed_external)
        .copied()
        .collect();
    let actual_names: BTreeSet<&str> = actual.keys().map(String::as_str).collect();
    if actual_names != expected_names {
        return Err(format!(
            "{} direct dependency declarations differ from policy: actual={actual_names:?}, expected={expected_names:?}",
            rule.name
        ));
    }

    let development_only: BTreeSet<&str> = rule.development_only.iter().copied().collect();
    if !development_only.is_subset(&expected_names) {
        return Err(format!(
            "{} dependency policy marks unknown dependencies as development-only",
            rule.name
        ));
    }
    for name in expected_names {
        let declarations = &actual[name];
        if declarations.len() != 1 {
            return Err(format!(
                "{} dependency {name} must have exactly one declaration, got {declarations:?}",
                rule.name
            ));
        }
        let declaration = declarations.first().expect("one declaration");
        let expected_kind = if development_only.contains(name) {
            DependencyKind::Development
        } else {
            DependencyKind::Normal
        };
        let matching_feature_policies: Vec<_> = rule
            .feature_policies
            .iter()
            .filter(|policy| policy.name == name)
            .collect();
        if matching_feature_policies.len() > 1 {
            return Err(format!(
                "{} dependency policy repeats feature settings for {name}",
                rule.name
            ));
        }
        let (expected_version, expected_default_features, expected_features) =
            matching_feature_policies
                .first()
                .map_or((None, true, BTreeSet::new()), |policy| {
                    (
                        policy.version_requirement,
                        policy.uses_default_features,
                        policy
                            .features
                            .iter()
                            .map(|feature| (*feature).to_owned())
                            .collect(),
                    )
                });
        if declaration.kind != expected_kind
            || expected_version.is_some_and(|expected| declaration.version_requirement != expected)
            || declaration.uses_default_features != expected_default_features
            || declaration.features != expected_features
            || declaration.optional
            || declaration.target.is_some()
            || declaration.rename.is_some()
        {
            return Err(format!(
                "{} dependency {name} settings differ from policy: actual={declaration:?}, expected_kind={expected_kind:?}, expected_version={expected_version:?}, expected_default_features={expected_default_features}, expected_features={expected_features:?}, expected_optional=false, expected_target=None, expected_rename=None",
                rule.name
            ));
        }
    }

    for policy in rule.feature_policies {
        if !actual.contains_key(policy.name) {
            return Err(format!(
                "{} dependency policy defines features for unknown dependency {}",
                rule.name, policy.name
            ));
        }
    }
    Ok(())
}

fn reject_unapproved(
    package: &str,
    kind: &str,
    actual: &BTreeSet<String>,
    allowed: &[&str],
) -> Result<(), String> {
    let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
    let unexpected: Vec<_> = actual
        .iter()
        .map(String::as_str)
        .filter(|dependency| !allowed.contains(dependency))
        .collect();
    if unexpected.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{package} has unapproved {kind} dependencies {unexpected:?}; update the architecture policy only after review"
        ))
    }
}

fn find_forbidden_path(
    graph: &BTreeMap<String, PackageDependencies>,
    start: &str,
    forbidden: &BTreeSet<String>,
) -> Option<Vec<String>> {
    let mut queue = VecDeque::from([vec![start.to_owned()]]);
    let mut visited = BTreeSet::new();
    while let Some(path) = queue.pop_front() {
        let current = path.last().expect("dependency path is nonempty");
        if current != start && forbidden.contains(current) {
            return Some(path);
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        if let Some(dependencies) = graph.get(current) {
            for dependency in &dependencies.local {
                let mut next = path.clone();
                next.push(dependency.clone());
                queue.push_back(next);
            }
        }
    }
    None
}

fn dependencies(local: &[&str]) -> PackageDependencies {
    PackageDependencies {
        local: local
            .iter()
            .map(|dependency| (*dependency).to_owned())
            .collect(),
        ..PackageDependencies::default()
    }
}

fn rust_sources(root: &std::path::Path) -> Vec<String> {
    fn collect(root: &std::path::Path, directory: &std::path::Path, files: &mut Vec<String>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace(std::path::MAIN_SEPARATOR, "/"),
                );
            }
        }
    }

    let mut files = Vec::new();
    collect(root, root, &mut files);
    files.sort();
    files
}
