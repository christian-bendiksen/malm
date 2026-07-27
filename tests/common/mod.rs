//! Shared integration-test environment for the Malm CLI.

#![allow(dead_code)]

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use malm::{Engine, EngineConfig, EnginePorts, StoreAccess};
use malm_types::DeploymentName;

const TEST_TIMEOUT: Duration = Duration::from_secs(120);

pub struct TestEnv {
    root: tempfile::TempDir,
}

impl TestEnv {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("create test tempdir");
        for directory in ["home", "state", "repo"] {
            std::fs::create_dir(root.path().join(directory)).expect("create test directory");
        }
        std::fs::set_permissions(
            root.path().join("state"),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("secure test state home");
        Self { root }
    }

    pub fn engine(&self) -> Engine {
        Engine::new(
            EngineConfig::from_state_home(self.state_home(), StoreAccess::ReadWrite)
                .expect("valid state home")
                .with_target_authority(
                    DeploymentName::new("home").expect("static deployment name"),
                    self.home(),
                )
                .expect("valid target authority"),
            EnginePorts::system(),
        )
    }

    pub fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    pub fn repo(&self) -> PathBuf {
        self.root.path().join("repo")
    }

    pub fn state_home(&self) -> PathBuf {
        self.root.path().join("state")
    }

    pub fn state_root(&self) -> PathBuf {
        self.state_home().join("malm")
    }

    pub fn malm(&self, arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_malm"));
        command
            .args(arguments)
            .env("HOME", self.home())
            .env("XDG_STATE_HOME", self.state_home())
            .env_remove("MALM_FAILPOINT");
        run_with_timeout(command)
    }

    pub fn malm_without_repo(&self, arguments: &[&str]) -> Output {
        self.malm(arguments)
    }
}

fn run_with_timeout(mut command: Command) -> Output {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn malm binary");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_thread = std::thread::spawn(move || drain_to_vec(stdout));
    let stderr_thread = std::thread::spawn(move || drain_to_vec(stderr));

    let deadline = std::time::Instant::now() + TEST_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
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
            "malm binary exceeded {}s test timeout\nstdout:\n{}\nstderr:\n{}",
            TEST_TIMEOUT.as_secs(),
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        ),
    }
}

fn drain_to_vec(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.read_to_end(&mut bytes);
    bytes
}
