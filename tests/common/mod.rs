//! Shared integration test helpers.
//!
//! Each test runs the real `malm` binary with isolated home, state, config,
//! and repository directories.

#![allow(dead_code)]

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// Kill a hung malm process instead of blocking the test suite indefinitely.
const TEST_TIMEOUT: Duration = Duration::from_secs(120);

pub struct TestEnv {
    root: tempfile::TempDir,
}

impl TestEnv {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("create test tempdir");
        for dir in ["home", "state", "config", "repo"] {
            std::fs::create_dir_all(root.path().join(dir)).expect("create test env dir");
        }
        Self { root }
    }

    /// A minimal config that deploys `files/bashrc` to `~/.bashrc`.
    pub fn with_basic_config() -> Self {
        let env = Self::new();
        env.write_repo_file("files/bashrc", "export TEST=1\n");
        env.write_config(&basic_config(&["file \"files/bashrc\" to=\"~/.bashrc\""]));
        env
    }

    pub fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    pub fn repo(&self) -> PathBuf {
        self.root.path().join("repo")
    }

    /// Malm's state root inside the isolated `XDG_STATE_HOME`.
    pub fn state_root(&self) -> PathBuf {
        self.root.path().join("state/malm")
    }

    pub fn transactions_dir(&self) -> PathBuf {
        self.state_root().join("transactions")
    }

    pub fn state_dir(&self, namespace: &str) -> PathBuf {
        self.state_root().join("states").join(namespace)
    }

    pub fn transaction_count(&self) -> usize {
        match std::fs::read_dir(self.transactions_dir()) {
            Ok(entries) => entries.count(),
            Err(_) => 0,
        }
    }

    pub fn write_repo_file(&self, rel: &str, contents: &str) {
        let path = self.repo().join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create repo subdir");
        }
        std::fs::write(path, contents).expect("write repo file");
    }

    pub fn write_config(&self, kdl: &str) {
        self.write_repo_file("malm.kdl", kdl);
    }

    /// Run malm without asserting its exit status.
    pub fn malm(&self, args: &[&str]) -> Output {
        self.malm_with_env(args, &[])
    }

    /// Run without the repository override to exercise source-less resolution.
    pub fn malm_without_repo(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_malm"));
        cmd.args(args)
            .env("HOME", self.root.path().join("home"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env_remove("MALM_FAILPOINT");
        run_with_timeout(cmd)
    }

    /// Run malm with extra environment variables such as `MALM_FAILPOINT`.
    pub fn malm_with_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_malm"));
        cmd.arg("--repo")
            .arg(self.repo())
            .args(args)
            .env("HOME", self.root.path().join("home"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env_remove("MALM_FAILPOINT");
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        run_with_timeout(cmd)
    }

    /// Require a successful run and return stdout.
    pub fn ok(&self, args: &[&str]) -> String {
        let output = self.malm(args);
        assert!(
            output.status.success(),
            "malm {args:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Require a failed run and return its combined output.
    pub fn fail(&self, args: &[&str]) -> String {
        let output = self.malm(args);
        assert!(
            !output.status.success(),
            "malm {args:?} unexpectedly succeeded\nstdout:\n{}",
            String::from_utf8_lossy(&output.stdout),
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    pub fn apply_ok(&self) -> String {
        self.ok(&["apply", "-y"])
    }

    /// Require `apply -y` to abort at the selected failpoint.
    pub fn apply_expect_crash(&self, failpoint: &str) {
        let output = self.malm_with_env(&["apply", "-y"], &[("MALM_FAILPOINT", failpoint)]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains("failpoint"),
            "expected apply to abort at failpoint {failpoint}\nstatus: {:?}\nstderr:\n{stderr}",
            output.status,
        );
    }

    /// Recorded transaction IDs from oldest to newest.
    pub fn transaction_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = match std::fs::read_dir(self.transactions_dir()) {
            Ok(entries) => entries
                .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
                .collect(),
            Err(_) => Vec::new(),
        };
        ids.sort();
        ids
    }

    pub fn manifest_json(&self, id: &str) -> serde_json::Value {
        let path = self.transactions_dir().join(id).join("manifest.json");
        let raw = std::fs::read_to_string(&path).expect("read transaction manifest");
        serde_json::from_str(&raw).expect("parse transaction manifest")
    }

    pub fn ops_journal_exists(&self, id: &str) -> bool {
        self.transactions_dir().join(id).join("ops.jsonl").is_file()
    }

    /// The target of `states/<ns>/current`, if it exists.
    pub fn source_pointer(&self, namespace: &str) -> Option<PathBuf> {
        std::fs::read_link(self.state_dir(namespace).join("current")).ok()
    }

    /// The parsed `states/<ns>/state.json`, if present.
    pub fn state_record(&self, namespace: &str) -> Option<serde_json::Value> {
        let raw = std::fs::read_to_string(self.state_dir(namespace).join("state.json")).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// The state record's mode tag ("enabled" / "disabled" / "destroyed").
    pub fn state_mode(&self, namespace: &str) -> Option<String> {
        Some(self.state_record(namespace)?["mode"].as_str()?.to_owned())
    }

    pub fn deployed_bashrc(&self) -> PathBuf {
        self.home().join(".bashrc")
    }

    pub fn assert_bashrc_deployed(&self, expected_contents: &str) {
        let link = self.deployed_bashrc();
        let meta = std::fs::symlink_metadata(&link).expect("deployed .bashrc missing");
        assert!(
            meta.file_type().is_symlink(),
            "deployed .bashrc is not a symlink"
        );
        let contents = std::fs::read_to_string(&link).expect("read deployed .bashrc");
        assert_eq!(contents, expected_contents, "deployed .bashrc contents");
    }
}

/// A minimal v2 config with one module activated by the default profile.
pub fn basic_config(outputs: &[&str]) -> String {
    let body: String = outputs
        .iter()
        .map(|line| format!("        {line}\n"))
        .collect();
    format!(
        "config target=\"~\" default-profile=\"main\"\n\
         module \"basic\" {{\n    outputs {{\n{body}    }}\n}}\n\
         profile \"main\" {{ use \"basic\" }}\n"
    )
}

/// Run a command with piped output and enforce [`TEST_TIMEOUT`].
///
/// Drain both pipes while the child runs so full buffers cannot deadlock it.
/// On timeout, kill and reap the child before reporting its partial output.
fn run_with_timeout(mut cmd: Command) -> Output {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn malm binary");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_thread = std::thread::spawn(move || drain_to_vec(stdout));
    let stderr_thread = std::thread::spawn(move || drain_to_vec(stderr));

    let deadline = std::time::Instant::now() + TEST_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("failed to wait on malm: {error}"),
        }
    };

    let stdout = stdout_thread.join().expect("drain stdout thread");
    let stderr = stderr_thread.join().expect("drain stderr thread");

    match status {
        Some(status) => Output {
            status,
            stdout,
            stderr,
        },
        None => panic!(
            "malm binary exceeded {}s test timeout\n\
             --- stdout ---\n{}\n\
             --- stderr ---\n{}",
            TEST_TIMEOUT.as_secs(),
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        ),
    }
}

fn drain_to_vec(mut reader: impl Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf);
    buf
}
