mod common;

use std::path::Path;

use common::TestEnv;

#[test]
fn json_success_and_error_are_single_envelopes() {
    let env = TestEnv::new();

    let success = env.malm_without_repo(&["store", "status", "--format", "json"]);
    assert!(success.status.success());
    assert!(success.stderr.is_empty());
    assert_eq!(
        success.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let success: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_cli_envelope(&success);
    assert_eq!(success["schema_version"], 1);
    assert_eq!(success["command"], "store.status");
    assert_eq!(success["outcome"], "ok");
    assert_eq!(success["data"]["status"], "absent");

    assert!(env.malm_without_repo(&["store", "init"]).status.success());
    let failure = env.malm_without_repo(&["plan", "show", "plan:01234567", "--format", "json"]);
    assert_eq!(failure.status.code(), Some(2));
    assert!(failure.stdout.is_empty());
    assert_eq!(
        failure.stderr.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let failure: serde_json::Value = serde_json::from_slice(&failure.stderr).unwrap();
    assert_cli_envelope(&failure);
    assert_eq!(failure["schema_version"], 1);
    assert_eq!(failure["command"], "plan.show");
    assert_eq!(failure["outcome"], "error");
    assert_eq!(failure["error"]["code"], "plan-not-found");
}

#[test]
fn absent_store_errors_carry_the_typed_store_not_ready_code_and_help() {
    let env = TestEnv::new();

    let json = env.malm_without_repo(&["plan", "list", "--format", "json"]);
    assert_eq!(json.status.code(), Some(2));
    assert!(json.stdout.is_empty());
    let envelope: serde_json::Value = serde_json::from_slice(&json.stderr).unwrap();
    assert_cli_envelope(&envelope);
    assert_eq!(envelope["error"]["code"], "store-not-ready");
    assert_eq!(envelope["error"]["category"], "conflict");
    assert!(
        envelope["error"]["help"]
            .as_str()
            .unwrap()
            .contains("malm store init")
    );

    let human = env.malm_without_repo(&["plan", "list"]);
    assert_eq!(human.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(stderr.contains("error[store-not-ready]"), "{stderr}");
    assert!(stderr.contains("malm store init"), "{stderr}");
}

#[test]
fn json_argument_errors_use_the_error_envelope() {
    let env = TestEnv::new();
    let failure = env.malm_without_repo(&["store", "status", "--format", "json", "--unsupported"]);

    assert_eq!(failure.status.code(), Some(2));
    assert!(failure.stdout.is_empty());
    assert_eq!(
        failure.stderr.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let failure: serde_json::Value = serde_json::from_slice(&failure.stderr).unwrap();
    assert_cli_envelope(&failure);
    assert_eq!(failure["schema_version"], 1);
    assert_eq!(failure["command"], "malm");
    assert_eq!(failure["outcome"], "error");
    assert_eq!(failure["error"]["code"], "invalid-request");
}

#[test]
fn machine_parse_errors_do_not_use_the_cli_json_envelope() {
    let env = TestEnv::new();
    let failure = env.malm_without_repo(&["machine", "--format", "json"]);

    assert_eq!(failure.status.code(), Some(2));
    assert!(failure.stdout.is_empty());
    assert!(serde_json::from_slice::<serde_json::Value>(&failure.stderr).is_err());
}

#[test]
fn json_error_messages_respect_the_schema_bound() {
    let env = TestEnv::new();
    let unsupported = format!("--{}", "x".repeat(9_000));
    let failure = env.malm_without_repo(&["store", "status", "--format", "json", &unsupported]);

    assert_eq!(failure.status.code(), Some(2));
    let failure: serde_json::Value = serde_json::from_slice(&failure.stderr).unwrap();
    assert_cli_envelope(&failure);
    assert!(
        failure["error"]["message"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            <= 8_192
    );
}

#[test]
fn directory_conflict_diagnostics_use_the_full_cli_v1_bound() {
    let diagnostics = (0..malm::MAX_DIRECTORY_CONFLICT_PATHS)
        .map(|index| {
            serde_json::json!({
                "severity": "error",
                "code": "directory-occupancy-conflict",
                "message": format!("/home/example/.config/blocker-{index:03}"),
            })
        })
        .collect::<Vec<_>>();
    let mut envelope = serde_json::json!({
        "schema_version": 1,
        "command": "plan.create",
        "outcome": "error",
        "data": null,
        "diagnostics": diagnostics,
        "error": {
            "category": "conflict",
            "code": "unsafe-target",
            "message": "target preparation is blocked by 257 directory occupancy conflicts (1 additional path omitted)",
            "help": "Back up, move, or remove every listed directory before retrying.",
        },
    });
    assert_cli_envelope(&envelope);

    envelope["diagnostics"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "severity": "error",
            "code": "directory-occupancy-conflict",
            "message": "/home/example/.config/overflow",
        }));
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/cli/v1/envelope.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::options().build(&schema).unwrap();
    assert!(!validator.is_valid(&envelope));
}

#[test]
fn redirected_human_output_has_no_ansi_or_progress() {
    let env = TestEnv::new();
    let output = env.malm_without_repo(&["store", "status"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.windows(2).any(|window| window == b"\x1b["));
    let human = String::from_utf8(output.stdout).unwrap();
    assert!(human.contains("Store is not initialized"));
    assert!(human.contains("malm store init"));
}

#[test]
fn human_adapters_use_only_the_shared_fallible_writer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli");
    for path in files_below(&root) {
        if path.file_name().is_some_and(|name| name == "output.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        for forbidden in ["print!(", "println!(", "eprint!(", "eprintln!("] {
            assert!(
                !source.contains(forbidden),
                "{} bypasses shared output with {forbidden}",
                path.display()
            );
        }
    }
}

fn files_below(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn assert_cli_envelope(envelope: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/cli/v1/envelope.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::options().build(&schema).unwrap();
    assert!(
        validator.is_valid(envelope),
        "runtime envelope failed schema: {:?}",
        validator.iter_errors(envelope).collect::<Vec<_>>()
    );
}
