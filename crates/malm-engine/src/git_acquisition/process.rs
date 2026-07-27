use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::Instant;

use malm_pack::PackSubdir;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags, openat2, statat};
use rustix::process::{
    Pid, Resource, Rlimit, Signal, WaitId, WaitIdOptions, getrlimit, kill_process_group, setrlimit,
    waitid,
};

use super::{
    GitAcquisitionConfig, GitAcquisitionIssue, GitCommandStage, GitObjectFormat, GitOutputStream,
    read_pack_stream,
};
use crate::ports::{GitPackFile, GitProcessPort, SystemGitProcessPort};

const STDOUT_OVERFLOW: u8 = 1;
const STDERR_OVERFLOW: u8 = 2;
const MAX_SCRATCH_SCAN_ENTRIES: usize = 500_000;
const MAX_SCRATCH_SCAN_DEPTH: usize = 128;
const MAX_SCRATCH_SCAN_DURATION: std::time::Duration = std::time::Duration::from_secs(1);
const SCRATCH_DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const SCRATCH_RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

#[cfg(target_arch = "x86")]
const NATIVE_AUDIT_ARCH: u32 = 0x4000_0003;
#[cfg(target_arch = "x86_64")]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "m68k")]
const NATIVE_AUDIT_ARCH: u32 = 0x0000_0004;
#[cfg(all(
    any(target_arch = "mips", target_arch = "mips32r6"),
    target_endian = "big"
))]
const NATIVE_AUDIT_ARCH: u32 = 0x0000_0008;
#[cfg(all(
    any(target_arch = "mips", target_arch = "mips32r6"),
    target_endian = "little"
))]
const NATIVE_AUDIT_ARCH: u32 = 0x4000_0008;
#[cfg(all(
    any(target_arch = "mips64", target_arch = "mips64r6"),
    target_pointer_width = "64",
    target_endian = "big"
))]
const NATIVE_AUDIT_ARCH: u32 = 0x8000_0008;
#[cfg(all(
    any(target_arch = "mips64", target_arch = "mips64r6"),
    target_pointer_width = "64",
    target_endian = "little"
))]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_0008;
#[cfg(all(
    any(target_arch = "mips64", target_arch = "mips64r6"),
    target_pointer_width = "32",
    target_endian = "big"
))]
const NATIVE_AUDIT_ARCH: u32 = 0xa000_0008;
#[cfg(all(
    any(target_arch = "mips64", target_arch = "mips64r6"),
    target_pointer_width = "32",
    target_endian = "little"
))]
const NATIVE_AUDIT_ARCH: u32 = 0xe000_0008;
#[cfg(all(target_arch = "powerpc", target_endian = "big"))]
const NATIVE_AUDIT_ARCH: u32 = 0x0000_0014;
#[cfg(all(target_arch = "powerpc64", target_endian = "big"))]
const NATIVE_AUDIT_ARCH: u32 = 0x8000_0015;
#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_0015;
#[cfg(target_arch = "s390x")]
const NATIVE_AUDIT_ARCH: u32 = 0x8000_0016;
#[cfg(all(target_arch = "arm", target_endian = "big"))]
const NATIVE_AUDIT_ARCH: u32 = 0x0000_0028;
#[cfg(all(target_arch = "arm", target_endian = "little"))]
const NATIVE_AUDIT_ARCH: u32 = 0x4000_0028;
#[cfg(target_arch = "sparc64")]
const NATIVE_AUDIT_ARCH: u32 = 0x8000_002b;
#[cfg(target_arch = "hexagon")]
const NATIVE_AUDIT_ARCH: u32 = 0x0000_00a4;
#[cfg(target_arch = "aarch64")]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;
#[cfg(target_arch = "riscv32")]
const NATIVE_AUDIT_ARCH: u32 = 0x4000_00f3;
#[cfg(target_arch = "riscv64")]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_00f3;
#[cfg(target_arch = "csky")]
const NATIVE_AUDIT_ARCH: u32 = 0x4000_00fc;
#[cfg(target_arch = "loongarch64")]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_0102;
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "csky",
    target_arch = "hexagon",
    target_arch = "loongarch64",
    target_arch = "m68k",
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "sparc64",
    target_arch = "x86",
    target_arch = "x86_64"
)))]
compile_error!("Git process confinement is not defined for this architecture");
#[cfg(all(target_arch = "powerpc", target_endian = "little"))]
compile_error!("Git process confinement is not defined for 32-bit little-endian PowerPC");

pub(super) struct GitRunner<'a> {
    config: &'a GitAcquisitionConfig,
    scratch: &'a File,
}

impl<'a> GitRunner<'a> {
    pub(super) const fn new(config: &'a GitAcquisitionConfig, scratch: &'a File) -> Self {
        Self { config, scratch }
    }

    pub(super) fn initialize(
        &self,
        object_format: &str,
        output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        self.run_control(
            GitCommandStage::Initialize,
            [
                OsStr::new("init"),
                OsStr::new("--bare"),
                OsStr::new("--quiet"),
                OsStr::new(if object_format == "sha1" {
                    "--object-format=sha1"
                } else {
                    "--object-format=sha256"
                }),
                OsStr::new("."),
            ],
            output_limit,
            None,
        )?;
        Ok(())
    }

    pub(super) fn fetch(
        &self,
        url: &str,
        oid: &str,
        output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        self.run_control(
            GitCommandStage::Fetch,
            [
                OsStr::new("--git-dir=."),
                OsStr::new("fetch"),
                OsStr::new("--quiet"),
                OsStr::new("--no-progress"),
                OsStr::new("--no-tags"),
                OsStr::new("--no-write-fetch-head"),
                OsStr::new("--no-recurse-submodules"),
                OsStr::new("--no-auto-maintenance"),
                OsStr::new("--no-write-commit-graph"),
                OsStr::new("--depth=1"),
                OsStr::new(url),
                OsStr::new(oid),
            ],
            output_limit,
            Some(self.config.transfer_limit()),
        )?;
        Ok(())
    }

    pub(super) fn read_pack(
        &self,
        format: GitObjectFormat,
        commit_oid: &str,
        subdir: &PackSubdir,
    ) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
        let stage = GitCommandStage::ReadObjects;
        let mut command = self.command([
            OsStr::new("--git-dir=."),
            OsStr::new("cat-file"),
            OsStr::new("--batch"),
        ]);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|source| process_io(stage, "spawn Git", source))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| process_io(stage, "open Git stdin", missing_pipe()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| process_io(stage, "open Git stdout", missing_pipe()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| process_io(stage, "open Git stderr", missing_pipe()))?;

        let commit_oid = commit_oid.to_owned();
        let subdir = subdir.clone();
        let worker =
            thread::spawn(move || read_pack_stream(stdout, stdin, format, &commit_oid, &subdir));
        let overflow = Arc::new(AtomicU8::new(0));
        let stderr_thread = spawn_drain(stderr, 64 * 1024, Arc::clone(&overflow), STDERR_OVERFLOW);
        let wait = supervise(
            &mut child,
            stage,
            self.config,
            &overflow,
            false,
            64 * 1024,
            None,
        );
        let worker_result = worker
            .join()
            .map_err(|_| process_io(stage, "join Git object reader", thread_panicked()))?;
        let stderr = join_drain(stderr_thread, stage, "join Git stderr reader")?;
        let status = wait?;
        check_output_limit(stage, &overflow, false, 64 * 1024)?;

        if let Err(error) = worker_result {
            return Err(error);
        }
        if !status.success() {
            return Err(process_failed(stage, status, &stderr.bytes));
        }
        worker_result
    }

    fn run_control<'b>(
        &self,
        stage: GitCommandStage,
        args: impl IntoIterator<Item = &'b OsStr>,
        output_limit: u64,
        transfer_limit: Option<u64>,
    ) -> Result<Vec<u8>, GitAcquisitionIssue> {
        let scratch_budget = transfer_limit
            .map(|limit| {
                scratch_usage(
                    self.scratch,
                    Instant::now() + MAX_SCRATCH_SCAN_DURATION,
                    u64::MAX,
                )
                .map(|baseline| ScratchBudget {
                    root: self.scratch,
                    baseline,
                    limit,
                })
                .map_err(|source| map_scratch_scan_error(stage, self.config, source))
            })
            .transpose()?;
        let mut command = self.command(args);
        if let Some(limit) = transfer_limit {
            apply_file_size_limit(&mut command, limit);
        }
        run_piped(command, stage, self.config, output_limit, scratch_budget)
    }

    fn command<'b>(&self, args: impl IntoIterator<Item = &'b OsStr>) -> Command {
        configured_command(self.config, &proc_fd_path(self.scratch), args)
    }
}

fn configured_command<'a>(
    config: &GitAcquisitionConfig,
    current_dir: &Path,
    args: impl IntoIterator<Item = &'a OsStr>,
) -> Command {
    let mut command = Command::new(config.executable());
    command
        .current_dir(current_dir)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("HOME", "/dev/null")
        .env("XDG_CONFIG_HOME", "/dev/null")
        .env("TMPDIR", ".")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GCM_INTERACTIVE", "never")
        .env("GIT_ALLOW_PROTOCOL", "https")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_LITERAL_PATHSPECS", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_FLUSH", "1")
        .arg("--no-pager");
    for value in [
        "core.hooksPath=/dev/null",
        "credential.helper=",
        "credential.interactive=never",
        "protocol.file.allow=never",
        "protocol.ext.allow=never",
        "protocol.https.allow=always",
        "fetch.fsckObjects=true",
        "transfer.fsckObjects=true",
        "gc.auto=0",
        "maintenance.auto=false",
        "fetch.writeCommitGraph=false",
        "http.followRedirects=false",
        "http.lowSpeedLimit=1024",
        "http.lowSpeedTime=60",
    ] {
        command.arg("-c").arg(value);
    }
    command.args(args).process_group(0);
    apply_process_group_confinement(&mut command);
    command
}

fn resolve_revision(
    config: &GitAcquisitionConfig,
    url: &str,
    selector: &str,
    output_limit: u64,
) -> Result<String, GitAcquisitionIssue> {
    let stage = GitCommandStage::ResolveSelector;
    let command = configured_command(
        config,
        Path::new("/"),
        [
            OsStr::new("ls-remote"),
            OsStr::new("--refs"),
            OsStr::new("--exit-code"),
            OsStr::new("--"),
            OsStr::new(url),
            OsStr::new(selector),
        ],
    );
    let stdout = run_piped(command, stage, config, output_limit, None)?;
    parse_selector_output(&stdout, selector)
}

/// Runs one fully piped Git subprocess and returns its stdout.
///
/// Both stdout and stderr are drained by dedicated threads under the same
/// byte limit while `supervise` enforces the wall-clock and scratch budgets,
/// so neither stream can deadlock the child or grow unbounded. A non-zero exit
/// reports the captured stderr.
fn run_piped(
    mut command: Command,
    stage: GitCommandStage,
    config: &GitAcquisitionConfig,
    output_limit: u64,
    scratch_budget: Option<ScratchBudget<'_>>,
) -> Result<Vec<u8>, GitAcquisitionIssue> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|source| process_io(stage, "spawn Git", source))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| process_io(stage, "open Git stdout", missing_pipe()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| process_io(stage, "open Git stderr", missing_pipe()))?;
    let overflow = Arc::new(AtomicU8::new(0));
    let stdout_thread = spawn_drain(stdout, output_limit, Arc::clone(&overflow), STDOUT_OVERFLOW);
    let stderr_thread = spawn_drain(stderr, output_limit, Arc::clone(&overflow), STDERR_OVERFLOW);
    let wait = supervise(
        &mut child,
        stage,
        config,
        &overflow,
        true,
        output_limit,
        scratch_budget,
    );
    let stdout = join_drain(stdout_thread, stage, "join Git stdout reader")?;
    let stderr = join_drain(stderr_thread, stage, "join Git stderr reader")?;
    let status = wait?;
    check_output_limit(stage, &overflow, true, output_limit)?;
    if !status.success() {
        return Err(process_failed(stage, status, &stderr.bytes));
    }
    Ok(stdout.bytes)
}

fn parse_selector_output(bytes: &[u8], selector: &str) -> Result<String, GitAcquisitionIssue> {
    let invalid = |detail: &'static str| GitAcquisitionIssue::InvalidSelectorOutput {
        detail: detail.to_owned(),
    };
    let Some(record) = bytes.strip_suffix(b"\n") else {
        return Err(invalid("output must contain one newline-terminated record"));
    };
    if record.is_empty() || record.contains(&b'\n') || record.contains(&b'\r') {
        return Err(invalid("output must contain exactly one record"));
    }
    let mut fields = record.split(|byte| *byte == b'\t');
    let oid = fields
        .next()
        .ok_or_else(|| invalid("record has no object ID"))?;
    let reference = fields
        .next()
        .ok_or_else(|| invalid("record has no reference name"))?;
    if fields.next().is_some() {
        return Err(invalid("record contains extra fields"));
    }
    if reference != selector.as_bytes() {
        return Err(invalid(
            "returned reference does not exactly match the selector",
        ));
    }
    if reference.ends_with(b"^{}") {
        return Err(invalid("peeled tag records are not accepted"));
    }
    if !matches!(oid.len(), 40 | 64)
        || !oid
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "object ID must be one full lowercase SHA-1 or SHA-256 value",
        ));
    }
    let oid = std::str::from_utf8(oid)
        .map_err(|_| invalid("object ID must contain ASCII hexadecimal digits"))?;
    let algorithm = if oid.len() == 40 { "sha1-" } else { "sha256-" };
    Ok(format!("{algorithm}{oid}"))
}

impl GitProcessPort for SystemGitProcessPort {
    fn resolve_revision(
        &self,
        config: &GitAcquisitionConfig,
        url: &str,
        selector: &str,
        output_limit: u64,
    ) -> Result<String, GitAcquisitionIssue> {
        resolve_revision(config, url, selector, output_limit)
    }

    fn initialize(
        &self,
        config: &GitAcquisitionConfig,
        scratch: &File,
        object_format: GitObjectFormat,
        output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        GitRunner::new(config, scratch).initialize(object_format.as_str(), output_limit)
    }

    fn fetch(
        &self,
        config: &GitAcquisitionConfig,
        scratch: &File,
        url: &str,
        object_id: &str,
        output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        GitRunner::new(config, scratch).fetch(url, object_id, output_limit)
    }

    fn read_pack(
        &self,
        config: &GitAcquisitionConfig,
        scratch: &File,
        object_format: GitObjectFormat,
        object_id: &str,
        subdir: &str,
    ) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
        let subdir = PackSubdir::new(subdir).map_err(|error| GitAcquisitionIssue::InvalidPath {
            detail: error.to_string(),
        })?;
        GitRunner::new(config, scratch).read_pack(object_format, object_id, &subdir)
    }
}

struct DrainResult {
    bytes: Vec<u8>,
    error: Option<io::Error>,
}

#[derive(Clone, Copy)]
struct ScratchBudget<'a> {
    root: &'a File,
    baseline: u64,
    limit: u64,
}

fn spawn_drain(
    mut reader: impl Read + Send + 'static,
    limit: u64,
    overflow: Arc<AtomicU8>,
    overflow_bit: u8,
) -> thread::JoinHandle<DrainResult> {
    thread::spawn(move || {
        let mut retained = Vec::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) => {
                    return DrainResult {
                        bytes: retained,
                        error: Some(error),
                    };
                }
            };
            total = total.saturating_add(read as u64);
            let remaining = limit.saturating_sub(retained.len() as u64) as usize;
            retained.extend_from_slice(&buffer[..read.min(remaining)]);
            if total > limit {
                overflow.fetch_or(overflow_bit, Ordering::Release);
            }
        }
        DrainResult {
            bytes: retained,
            error: None,
        }
    })
}

fn join_drain(
    handle: thread::JoinHandle<DrainResult>,
    stage: GitCommandStage,
    operation: &'static str,
) -> Result<DrainResult, GitAcquisitionIssue> {
    let result = handle
        .join()
        .map_err(|_| process_io(stage, operation, thread_panicked()))?;
    if let Some(source) = result.error {
        return Err(process_io(stage, "read Git output", source));
    }
    Ok(result)
}

fn supervise(
    child: &mut Child,
    stage: GitCommandStage,
    config: &GitAcquisitionConfig,
    overflow: &AtomicU8,
    watch_stdout: bool,
    output_limit: u64,
    scratch_budget: Option<ScratchBudget<'_>>,
) -> Result<ExitStatus, GitAcquisitionIssue> {
    let deadline = Instant::now() + config.timeout();
    loop {
        if let Err(error) = check_output_limit(stage, overflow, watch_stdout, output_limit) {
            kill_and_reap(child, stage)?;
            return Err(error);
        }
        if let Some(budget) = scratch_budget {
            let usage = match scratch_usage(
                budget.root,
                deadline,
                budget.baseline.saturating_add(budget.limit),
            ) {
                Ok(usage) => usage,
                Err(source) => {
                    kill_and_reap(child, stage)?;
                    return Err(map_scratch_scan_error(stage, config, source));
                }
            };
            if usage > budget.baseline.saturating_add(budget.limit) {
                kill_and_reap(child, stage)?;
                return Err(GitAcquisitionIssue::TransferLimitExceeded {
                    stage,
                    limit: budget.limit,
                });
            }
        }
        let exited = match process_exited(child, stage) {
            Ok(exited) => exited,
            Err(error) => {
                kill_and_reap(child, stage)?;
                return Err(error);
            }
        };
        if exited {
            // Stop helpers from retaining pipes or mutating scratch after supervision.
            kill_group(child, stage)?;
            let status = child
                .wait()
                .map_err(|source| process_io(stage, "read Git exit status", source))?;
            let final_scratch_usage = if let Some(budget) = scratch_budget {
                let usage = scratch_usage(
                    budget.root,
                    deadline,
                    budget.baseline.saturating_add(budget.limit),
                )
                .map_err(|source| map_scratch_scan_error(stage, config, source))?;
                if usage > budget.baseline.saturating_add(budget.limit) {
                    return Err(GitAcquisitionIssue::TransferLimitExceeded {
                        stage,
                        limit: budget.limit,
                    });
                }
                Some(usage)
            } else {
                None
            };
            if let (Some(budget), Some(usage)) = (scratch_budget, final_scratch_usage)
                && !status.success()
                && (status.signal() == Some(libc::SIGXFSZ)
                    || usage >= budget.baseline.saturating_add(budget.limit))
            {
                return Err(GitAcquisitionIssue::TransferLimitExceeded {
                    stage,
                    limit: budget.limit,
                });
            }
            return Ok(status);
        }
        if Instant::now() >= deadline {
            kill_and_reap(child, stage)?;
            return Err(GitAcquisitionIssue::Timeout {
                stage,
                limit: config.timeout(),
            });
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn check_output_limit(
    stage: GitCommandStage,
    overflow: &AtomicU8,
    watch_stdout: bool,
    limit: u64,
) -> Result<(), GitAcquisitionIssue> {
    let flags = overflow.load(Ordering::Acquire);
    let stream = if watch_stdout && flags & STDOUT_OVERFLOW != 0 {
        Some(GitOutputStream::Stdout)
    } else if flags & STDERR_OVERFLOW != 0 {
        Some(GitOutputStream::Stderr)
    } else {
        None
    };
    if let Some(stream) = stream {
        return Err(GitAcquisitionIssue::OutputLimitExceeded {
            stage,
            stream,
            limit,
        });
    }
    Ok(())
}

fn process_exited(child: &Child, stage: GitCommandStage) -> Result<bool, GitAcquisitionIssue> {
    let child_pid = Pid::from_child(child);
    loop {
        match waitid(
            WaitId::Pid(child_pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => return Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => {}
            Err(source) => {
                return Err(process_io(
                    stage,
                    "inspect Git process status",
                    io::Error::from(source),
                ));
            }
        }
    }
}

fn apply_file_size_limit(command: &mut Command, requested: u64) {
    let inherited = getrlimit(Resource::Fsize);
    let effective = inherited
        .current
        .into_iter()
        .chain(inherited.maximum)
        .fold(requested, u64::min);
    // SAFETY: setrlimit is async-signal-safe and the closure performs no allocation
    // or access to shared process state after fork.
    unsafe {
        command.pre_exec(move || {
            setrlimit(
                Resource::Fsize,
                Rlimit {
                    current: Some(effective),
                    maximum: Some(effective),
                },
            )
            .map_err(io::Error::from)
        });
    }
}

fn apply_process_group_confinement(command: &mut Command) {
    // SAFETY: the closure performs only async-signal-safe prctl calls and stack
    // initialization after fork.
    unsafe {
        command.pre_exec(install_process_group_confinement);
    }
}

fn install_process_group_confinement() -> io::Result<()> {
    const BPF_LOAD_WORD_ABSOLUTE: u16 = 0x20;
    const BPF_JUMP_EQUAL: u16 = 0x15;
    const BPF_AND: u16 = 0x54;
    const BPF_RETURN: u16 = 0x06;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_RETURN_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RETURN_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RETURN_KILL_PROCESS: u32 = 0x8000_0000;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    let denied = SECCOMP_RETURN_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1);
    let mut filters = [
        libc::sock_filter {
            code: BPF_LOAD_WORD_ABSOLUTE,
            jt: 0,
            jf: 0,
            k: u32::try_from(std::mem::offset_of!(libc::seccomp_data, arch)).unwrap_or(u32::MAX),
        },
        libc::sock_filter {
            code: BPF_JUMP_EQUAL,
            jt: 1,
            jf: 0,
            k: NATIVE_AUDIT_ARCH,
        },
        libc::sock_filter {
            code: BPF_RETURN,
            jt: 0,
            jf: 0,
            k: SECCOMP_RETURN_KILL_PROCESS,
        },
        libc::sock_filter {
            code: BPF_LOAD_WORD_ABSOLUTE,
            jt: 0,
            jf: 0,
            k: u32::try_from(std::mem::offset_of!(libc::seccomp_data, nr)).unwrap_or(u32::MAX),
        },
        libc::sock_filter {
            code: BPF_AND,
            jt: 0,
            jf: 0,
            k: !X32_SYSCALL_BIT,
        },
        libc::sock_filter {
            code: BPF_JUMP_EQUAL,
            jt: 0,
            jf: 1,
            k: (libc::SYS_setsid as u32) & !X32_SYSCALL_BIT,
        },
        libc::sock_filter {
            code: BPF_RETURN,
            jt: 0,
            jf: 0,
            k: denied,
        },
        libc::sock_filter {
            code: BPF_JUMP_EQUAL,
            jt: 0,
            jf: 1,
            k: (libc::SYS_setpgid as u32) & !X32_SYSCALL_BIT,
        },
        libc::sock_filter {
            code: BPF_RETURN,
            jt: 0,
            jf: 0,
            k: denied,
        },
        libc::sock_filter {
            code: BPF_RETURN,
            jt: 0,
            jf: 0,
            k: SECCOMP_RETURN_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: u16::try_from(filters.len()).unwrap_or(u16::MAX),
        filter: filters.as_mut_ptr(),
    };

    // SAFETY: prctl is called with the documented scalar arguments and a valid
    // filter-program pointer that remains live for the duration of the call.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: no_new_privs is set and `program` describes a valid classic BPF
    // filter over the seccomp syscall-number field.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            std::ptr::from_ref(&program),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn scratch_usage(directory: &File, deadline: Instant, cutoff: u64) -> io::Result<u64> {
    let mut scan = ScratchScan {
        entries: 0,
        total: 0,
        deadline,
        cutoff,
    };
    scan.directory(directory, 0)?;
    Ok(scan.total)
}

struct ScratchScan {
    entries: usize,
    total: u64,
    deadline: Instant,
    cutoff: u64,
}

impl ScratchScan {
    fn directory(&mut self, directory: &File, depth: usize) -> io::Result<()> {
        if depth > MAX_SCRATCH_SCAN_DEPTH {
            return Err(io::Error::other(
                "Git scratch nesting exceeds its scan limit",
            ));
        }
        self.ensure_deadline()?;
        let mut stream = Dir::read_from(directory).map_err(io::Error::from)?;
        while let Some(entry) = stream.read() {
            self.ensure_deadline()?;
            let entry = entry.map_err(io::Error::from)?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            if self.entries == MAX_SCRATCH_SCAN_ENTRIES {
                return Err(io::Error::other(
                    "Git scratch contains too many entries to measure safely",
                ));
            }
            self.entries += 1;
            let stat = match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => continue,
                Err(source) => return Err(io::Error::from(source)),
            };
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::RegularFile => {
                    let logical = u64::try_from(stat.st_size).unwrap_or(0);
                    let allocated = u64::try_from(stat.st_blocks)
                        .unwrap_or(0)
                        .saturating_mul(512);
                    self.total = self.total.saturating_add(logical.max(allocated));
                    if self.total > self.cutoff {
                        return Ok(());
                    }
                }
                FileType::Directory => {
                    let child = match openat2(
                        directory,
                        name,
                        SCRATCH_DIRECTORY_FLAGS,
                        Mode::empty(),
                        SCRATCH_RESOLVE_FLAGS,
                    ) {
                        Ok(child) => File::from(child),
                        Err(
                            rustix::io::Errno::NOENT
                            | rustix::io::Errno::NOTDIR
                            | rustix::io::Errno::LOOP,
                        ) => continue,
                        Err(source) => return Err(io::Error::from(source)),
                    };
                    self.directory(&child, depth + 1)?;
                    if self.total > self.cutoff {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn ensure_deadline(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Git scratch scan exceeded its deadline",
            ))
        } else {
            Ok(())
        }
    }
}

fn map_scratch_scan_error(
    stage: GitCommandStage,
    config: &GitAcquisitionConfig,
    source: io::Error,
) -> GitAcquisitionIssue {
    if source.kind() == io::ErrorKind::TimedOut {
        GitAcquisitionIssue::Timeout {
            stage,
            limit: config.timeout(),
        }
    } else {
        process_io(stage, "measure Git scratch usage", source)
    }
}

fn kill_and_reap(child: &mut Child, stage: GitCommandStage) -> Result<(), GitAcquisitionIssue> {
    kill_group(child, stage)?;
    child
        .wait()
        .map_err(|source| process_io(stage, "reap Git process", source))?;
    Ok(())
}

fn kill_group(child: &Child, stage: GitCommandStage) -> Result<(), GitAcquisitionIssue> {
    let group = Pid::from_child(child);
    match kill_process_group(group, Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => {}
        Err(source) => {
            return Err(process_io(
                stage,
                "kill bounded Git process group",
                io::Error::from(source),
            ));
        }
    }
    Ok(())
}

fn process_failed(
    stage: GitCommandStage,
    status: ExitStatus,
    stderr: &[u8],
) -> GitAcquisitionIssue {
    GitAcquisitionIssue::ProcessFailed {
        stage,
        code: status.code(),
        detail: sanitize_control_text(stderr),
    }
}

fn sanitize_control_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|character| *character == '\n' || *character == '\t' || !character.is_control())
        .collect::<String>()
        .trim()
        .to_owned()
}

fn process_io(
    stage: GitCommandStage,
    operation: &'static str,
    source: io::Error,
) -> GitAcquisitionIssue {
    GitAcquisitionIssue::ProcessIo {
        stage,
        operation,
        source,
    }
}

fn proc_fd_path(file: &File) -> PathBuf {
    PathBuf::from("/proc/self/fd").join(file.as_raw_fd().to_string())
}

fn missing_pipe() -> io::Error {
    io::Error::other("Git pipe was not configured")
}

fn thread_panicked() -> io::Error {
    io::Error::other("Git I/O worker panicked")
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use super::{apply_file_size_limit, apply_process_group_confinement, parse_selector_output};
    use crate::GitAcquisitionIssue;

    #[test]
    fn selector_parser_accepts_one_exact_full_oid_record() {
        let selector = "refs/heads/main";
        let sha1 = "1".repeat(40);
        let sha256 = "a".repeat(64);

        assert_eq!(
            parse_selector_output(format!("{sha1}\t{selector}\n").as_bytes(), selector).unwrap(),
            format!("sha1-{sha1}")
        );
        assert_eq!(
            parse_selector_output(format!("{sha256}\t{selector}\n").as_bytes(), selector).unwrap(),
            format!("sha256-{sha256}")
        );
    }

    #[test]
    fn selector_parser_rejects_ambiguity_peeling_and_nonexact_records() {
        let selector = "refs/heads/main";
        let oid = "1".repeat(40);
        for output in [
            format!("{oid}\t{selector}"),
            format!("{oid}\trefs/heads/other\n"),
            format!("{oid}\t{selector}^{{}}\n"),
            format!("{}\t{selector}\n", "1".repeat(39)),
            format!("{}\t{selector}\n", "A".repeat(40)),
            format!("{oid}\t{selector}\n{oid}\t{selector}\n"),
            format!("{oid} {selector}\n"),
            format!("{oid}\t{selector}\textra\n"),
        ] {
            assert!(matches!(
                parse_selector_output(output.as_bytes(), selector),
                Err(GitAcquisitionIssue::InvalidSelectorOutput { .. })
            ));
        }
    }

    #[test]
    fn child_cannot_raise_soft_file_limit_above_the_transfer_bound() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "test \"$(ulimit -S -f)\" = \"$(ulimit -H -f)\" && ! ulimit -S -f unlimited 2>/dev/null",
        ]);
        apply_file_size_limit(&mut command, 64 * 1024);

        let status = command.status().unwrap();
        assert!(status.success(), "child escaped its hard file-size bound");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn production_process_group_filter_blocks_setsid_and_setpgid() {
        // Verify that the production filter denies setsid and setpgid with
        // EPERM while leaving an allowed syscall usable.
        let mut command = Command::new("/bin/true");
        apply_process_group_confinement(&mut command);

        // SAFETY: the pre_exec closure only invokes async-signal-safe libc
        // syscalls and returns via the closure result; it allocates nothing and
        // holds no state.
        unsafe {
            command.pre_exec(|| {
                let setsid = libc::setsid();
                if setsid != -1 {
                    return Err(io::Error::other(
                        "setsid was not denied by the production seccomp filter",
                    ));
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                    return Err(io::Error::other("setsid denial was not EPERM"));
                }

                let setpgid = libc::setpgid(0, 0);
                if setpgid != -1 {
                    return Err(io::Error::other(
                        "setpgid was not denied by the production seccomp filter",
                    ));
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                    return Err(io::Error::other("setpgid denial was not EPERM"));
                }

                let pid = libc::getpid();
                if pid <= 0 {
                    return Err(io::Error::other(
                        "getpid failed after installing the production seccomp filter",
                    ));
                }

                Ok(())
            });
        }

        let status = command.status().unwrap();
        assert!(
            status.success(),
            "child failed; the production seccomp filter did not behave as expected: {status:?}"
        );
    }
}
