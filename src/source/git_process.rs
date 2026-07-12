//! Hardened `git` invocation: every command runs with ambient GIT_* state
//! scrubbed and security config pinned; errors redact credential URLs.

use crate::source::git_url::redact_url;
use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Hard wall-clock limit for any git subprocess. `http.lowSpeedTime` only
/// covers stalled HTTP transfers; a wedged subprocess (hung DNS, a
/// never-ending pack negotiation) must still be killable by Malm.
const GIT_TIMEOUT: Duration = Duration::from_secs(600);

/// Per-stream capture ceiling to keep hostile remote output from exhausting memory.
/// A process blocked after reaching the cap is still covered by the wall-clock timeout.
const MAX_GIT_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

fn git_timeout() -> Duration {
    std::env::var("MALM_GIT_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(GIT_TIMEOUT)
}

/// Poll the child against the deadline; on expiry kill it and fail.
fn wait_with_timeout(child: &mut Child, args: &[&OsStr]) -> Result<ExitStatus> {
    let timeout = git_timeout();
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("wait for git {}", args_display(args)))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "git {} exceeded the {}s timeout and was killed",
                args_display(args),
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn check_git_available() -> Result<()> {
    let status = git_command(&[OsStr::new("--version")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| {
            anyhow::anyhow!("git is not available; install git and ensure it is in PATH")
        })?;
    if !status.success() {
        anyhow::bail!("git is present but `git --version` failed with {status}");
    }
    Ok(())
}

fn git_command(args: &[&OsStr]) -> Command {
    let mut cmd = Command::new("git");
    // Malm's git invocations must not be steered by ambient configuration
    // or environment: an attacker-controlled ~/.gitconfig (core.fsmonitor,
    // credential helpers, url rewrites) or inherited GIT_* variables would
    // otherwise execute during clone/fetch.
    for (key, _) in std::env::vars_os() {
        if let Some(key_str) = key.to_str()
            && (key_str.starts_with("GIT_") || key_str.starts_with("GIT_CONFIG"))
        {
            cmd.env_remove(key);
        }
    }
    for config in [
        "protocol.file.allow=never",
        "protocol.ext.allow=never",
        "core.hooksPath=/dev/null",
        "http.lowSpeedLimit=1024",
        "http.lowSpeedTime=60",
    ] {
        cmd.arg("-c").arg(config);
    }
    cmd.args(args)
        .stdin(Stdio::null())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GCM_INTERACTIVE", "never")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ALLOW_PROTOCOL", "https");
    cmd
}

pub(super) fn git_run(args: &[&OsStr]) -> Result<()> {
    let mut child = git_command(args)
        .spawn()
        .context("failed to spawn git; ensure git is installed and in PATH")?;
    let status = wait_with_timeout(&mut child, args)?;
    if !status.success() {
        anyhow::bail!("git {} exited with {}", args_display(args), status);
    }
    Ok(())
}

pub(super) fn git_capture(args: &[&OsStr]) -> Result<String> {
    let mut child = git_command(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn git")?;

    // Read both pipes concurrently and cap each capture while the timeout polls.
    let drain = |stream: Option<Box<dyn Read + Send>>| {
        stream.map(|reader| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = reader.take(MAX_GIT_OUTPUT_BYTES).read_to_end(&mut buf);
                buf
            })
        })
    };
    let stdout_thread = drain(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let stderr_thread = drain(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );

    let status = wait_with_timeout(&mut child, args)?;
    let stdout = stdout_thread
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr_thread
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            anyhow::bail!("git {} failed (exit {})", args_display(args), status);
        } else {
            anyhow::bail!(
                "git {} failed (exit {}):\n{stderr}",
                args_display(args),
                status
            );
        }
    }
    Ok(String::from_utf8_lossy(&stdout).trim().to_owned())
}

fn args_display(args: &[&OsStr]) -> String {
    args.iter()
        .map(|arg| arg_display(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn arg_display(arg: &OsStr) -> String {
    let s = arg.to_string_lossy();

    if s.starts_with("https://") || s.starts_with("http://") {
        redact_url(&s)
    } else {
        s.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn git_commands_scrub_inherited_env_and_pin_config() {
        // Simulate inherited settings that could steer Git.
        unsafe {
            std::env::set_var("GIT_CONFIG_COUNT", "1");
            std::env::set_var("GIT_PROXY_COMMAND", "/tmp/evil");
        }

        let cmd = git_command(&[OsStr::new("--version")]);
        let envs: HashMap<_, _> = cmd.get_envs().collect();

        // `None` means the inherited variable is explicitly cleared.
        assert_eq!(envs.get(OsStr::new("GIT_CONFIG_COUNT")), Some(&None));
        assert_eq!(envs.get(OsStr::new("GIT_PROXY_COMMAND")), Some(&None));

        // Required hardening remains pinned after the scrub.
        let pinned = |key: &str| envs.get(OsStr::new(key)).copied().flatten();
        assert_eq!(pinned("GIT_CONFIG_GLOBAL"), Some(OsStr::new("/dev/null")));
        assert_eq!(pinned("GIT_CONFIG_NOSYSTEM"), Some(OsStr::new("1")));
        assert_eq!(pinned("GIT_TERMINAL_PROMPT"), Some(OsStr::new("0")));
        assert_eq!(pinned("GIT_ALLOW_PROTOCOL"), Some(OsStr::new("https")));

        unsafe {
            std::env::remove_var("GIT_CONFIG_COUNT");
            std::env::remove_var("GIT_PROXY_COMMAND");
        }
    }
}
