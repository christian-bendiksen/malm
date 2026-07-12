mod common;

use common::TestEnv;
use std::path::Path;

fn text_output_config(destination: &str) -> String {
    format!(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" {{ outputs {{ render \"{destination}\" format=\"text\" {{ @raw \"bad\" }} }} }}\n\
         profile \"p\" {{ use \"m\" }}\n"
    )
}

#[test]
fn render_rejects_destination_traversal() {
    let env = TestEnv::new();
    env.write_config(&text_output_config("../escaped"));
    let output_dir = env.repo().join("output");
    let escaped = env.repo().join("escaped");
    let output = env.fail(&["render", "--output", output_dir.to_str().unwrap()]);
    assert!(output.contains("without traversal"), "{output}");
    assert!(!escaped.exists());
}

#[test]
fn render_does_not_write_through_an_intermediate_symlink() {
    let env = TestEnv::new();
    env.write_config(&text_output_config("~/pwn"));
    let output_dir = env.repo().join("output");
    let outside = env.repo().join("outside");
    std::fs::create_dir_all(&output_dir).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, output_dir.join("HOME")).unwrap();

    let output = env.fail(&["render", "--output", output_dir.to_str().unwrap()]);
    assert!(output.contains("without following symlinks"), "{output}");
    assert!(!outside.join("pwn").exists());
}

#[test]
fn render_does_not_write_through_a_leaf_symlink() {
    let env = TestEnv::new();
    env.write_config(&text_output_config("leaf"));
    let output_dir = env.repo().join("output");
    let victim = env.repo().join("victim");
    std::fs::create_dir(&output_dir).unwrap();
    std::fs::write(&victim, "safe").unwrap();
    std::os::unix::fs::symlink(&victim, output_dir.join("leaf")).unwrap();

    env.fail(&["render", "--output", output_dir.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "safe");
}

#[test]
fn render_cli_rejects_an_empty_output_root() {
    let env = TestEnv::new();
    env.write_config(&text_output_config("file"));
    let output = env.fail(&["render", "--output", ""]);
    assert!(
        output.contains("a value is required for '--output <OUTPUT>'"),
        "{output}"
    );
}

#[test]
fn render_rejects_a_symlink_output_root() {
    let env = TestEnv::new();
    env.write_config(&text_output_config("pwn"));
    let outside = env.repo().join("outside");
    let output_dir = env.repo().join("output-link");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, &output_dir).unwrap();

    env.fail(&["render", "--output", output_dir.to_str().unwrap()]);
    assert!(!outside.join(Path::new("pwn")).exists());
}

#[test]
fn render_rejects_collisions_after_home_mapping_before_writing() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" { outputs {\n\
             render \"~/same\" format=\"text\" { @raw \"one\" }\n\
             render \"HOME/same\" format=\"text\" { @raw \"two\" }\n\
         } }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output_dir = env.repo().join("output");
    let output = env.fail(&["render", "--output", output_dir.to_str().unwrap()]);
    assert!(output.contains("after HOME/ABS mapping"), "{output}");
    assert!(
        !output_dir.exists(),
        "collision must be detected before writes"
    );
}

#[test]
fn render_rejects_destination_ancestor_relationships() {
    let env = TestEnv::new();
    env.write_config(
        "config target=\"~\" default-profile=\"p\"\n\
         module \"m\" { outputs {\n\
             render \"~/parent/child\" format=\"text\" { @raw \"child\" }\n\
             render \"HOME/parent\" format=\"text\" { @raw \"parent\" }\n\
         } }\n\
         profile \"p\" { use \"m\" }\n",
    );
    let output_dir = env.repo().join("output");
    let output = env.fail(&["render", "--output", output_dir.to_str().unwrap()]);
    assert!(output.contains("is an ancestor"), "{output}");
    assert!(
        !output_dir.exists(),
        "collision must be detected before writes"
    );
}
