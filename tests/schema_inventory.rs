use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const INVENTORY: &str = include_str!("../schemas/conformance-inventory.tsv");
const SCHEMA_FAMILIES: &[&str] = &["archive/v1", "cli/v1", "lock/v1", "machine/v1", "root/v1"];

fn files_below(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[derive(Debug)]
struct Evidence {
    mode: &'static str,
    schema: PathBuf,
    test: PathBuf,
    token: &'static str,
    exception: &'static str,
}

fn conformance_inventory() -> BTreeMap<PathBuf, Evidence> {
    let mut evidence = BTreeMap::new();
    for line in INVENTORY
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 6, "invalid schema inventory row: {line:?}");
        assert!(fields.iter().all(|field| !field.is_empty()));
        assert!(matches!(
            fields[1],
            "schema" | "valid" | "invalid" | "strict" | "decoder" | "exact"
        ));
        let contract = PathBuf::from(fields[0]);
        assert!(
            evidence
                .insert(
                    contract.clone(),
                    Evidence {
                        mode: fields[1],
                        schema: PathBuf::from(fields[2]),
                        test: PathBuf::from(fields[3]),
                        token: fields[4],
                        exception: fields[5],
                    },
                )
                .is_none(),
            "duplicate schema inventory entry {}",
            contract.display()
        );
    }
    evidence
}

fn is_schema_fixture(path: &Path) -> bool {
    let relative = path.strip_prefix("schemas").unwrap();
    SCHEMA_FAMILIES.iter().any(|family| {
        relative.starts_with(family)
            && relative.components().any(|component| {
                matches!(
                    component.as_os_str().to_str(),
                    Some("valid" | "malformed" | "unsupported")
                )
            })
    })
}

fn discovered_contracts(root: &Path) -> BTreeSet<PathBuf> {
    let mut discovered = files_below(&root.join("schemas"))
        .into_iter()
        .filter(|path| {
            let name = path.file_name().and_then(|name| name.to_str()).unwrap();
            name == "schema.json"
                || name.ends_with(".schema.json")
                || path
                    .components()
                    .any(|component| component.as_os_str() == "golden")
                || is_schema_fixture(path.strip_prefix(root).unwrap())
        })
        .map(|path| path.strip_prefix(root).unwrap().to_path_buf())
        .collect::<BTreeSet<_>>();
    discovered.insert(PathBuf::from(
        "crates/malm-format-component-api/wit/malm-format-component.wit",
    ));
    discovered
}

fn json_value(path: &Path) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_slice(&std::fs::read(path).unwrap())
}

#[test]
fn inventory_is_exact_and_all_registered_evidence_is_executable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let evidence = conformance_inventory();
    assert_eq!(
        evidence.keys().cloned().collect::<BTreeSet<_>>(),
        discovered_contracts(root)
    );

    for (contract, registration) in &evidence {
        assert!(
            root.join(contract).is_file(),
            "missing {}",
            contract.display()
        );
        if registration.token != "-" {
            let source =
                std::fs::read_to_string(root.join(&registration.test)).unwrap_or_else(|error| {
                    panic!("read evidence {}: {error}", registration.test.display())
                });
            assert!(
                source.contains(registration.token),
                "evidence {} does not reference {} with token {:?}",
                registration.test.display(),
                contract.display(),
                registration.token
            );
        }
        if matches!(registration.mode, "strict" | "decoder" | "exact") {
            assert_ne!(registration.exception, "-");
        } else {
            assert_eq!(registration.exception, "-");
        }
    }
}

#[test]
fn normative_json_schemas_compile_and_enforce_the_registered_fixture_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let evidence = conformance_inventory();
    let schemas = evidence
        .iter()
        .filter(|(_, registration)| registration.mode == "schema")
        .map(|(path, _)| {
            let value = json_value(&root.join(path))
                .unwrap_or_else(|error| panic!("parse schema {}: {error}", path.display()));
            assert_eq!(
                value["$schema"],
                "https://json-schema.org/draft/2020-12/schema",
                "{} does not declare the normative draft",
                path.display()
            );
            jsonschema::meta::validate(&value)
                .unwrap_or_else(|error| panic!("meta-validate {}: {error}", path.display()));
            (path.clone(), value)
        })
        .collect::<BTreeMap<_, _>>();

    let mut registry = jsonschema::Registry::new();
    for (path, schema) in &schemas {
        let id = schema["$id"]
            .as_str()
            .unwrap_or_else(|| panic!("{} has no string $id", path.display()));
        registry = registry
            .add(id, schema)
            .unwrap_or_else(|error| panic!("register {}: {error}", path.display()));
    }
    let registry = registry
        .prepare()
        .unwrap_or_else(|error| panic!("prepare schema registry: {error}"));

    for (path, schema) in &schemas {
        jsonschema::options()
            .with_registry(&registry)
            .build(schema)
            .unwrap_or_else(|error| panic!("compile {}: {error}", path.display()));
    }

    for (fixture, registration) in evidence
        .iter()
        .filter(|(_, registration)| matches!(registration.mode, "valid" | "invalid" | "strict"))
    {
        let schema = schemas.get(&registration.schema).unwrap_or_else(|| {
            panic!(
                "{} references unregistered schema {}",
                fixture.display(),
                registration.schema.display()
            )
        });
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(schema)
            .unwrap_or_else(|error| {
                panic!(
                    "compile {} for {}: {error}",
                    registration.schema.display(),
                    fixture.display()
                )
            });
        let value = json_value(&root.join(fixture));
        match registration.mode {
            "valid" => {
                let value = value
                    .unwrap_or_else(|error| panic!("parse valid {}: {error}", fixture.display()));
                assert!(
                    validator.is_valid(&value),
                    "valid fixture {} failed {}: {:?}",
                    fixture.display(),
                    registration.schema.display(),
                    validator.iter_errors(&value).collect::<Vec<_>>()
                );
            }
            "invalid" => {
                if let Ok(value) = value {
                    assert!(
                        !validator.is_valid(&value),
                        "malformed fixture {} unexpectedly passed {}",
                        fixture.display(),
                        registration.schema.display()
                    );
                }
            }
            "strict" => {
                let value = value.unwrap_or_else(|error| {
                    panic!(
                        "strict exception {} is not JSON: {error}",
                        fixture.display()
                    )
                });
                assert!(
                    validator.is_valid(&value),
                    "strict exception {} is already representable by {}",
                    fixture.display(),
                    registration.schema.display()
                );
            }
            _ => unreachable!(),
        }
    }
}
