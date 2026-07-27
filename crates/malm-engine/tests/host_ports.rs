use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use malm_engine::{
    ApprovalV1, CommitRequestV1, PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1,
    PrepareRequestV1,
};
use malm_engine::{
    DiagnosticEvent, DiagnosticSink, DirectorySafetyIssue, Engine, EngineConfig, EngineError,
    EngineFailureKind, EngineOperation, EnginePorts, GitAcquisitionConfig, GitAcquisitionIssue,
    GitCommandStage, GitObjectFormat, GitPackFile, GitProcessPort, LockOperationError,
    LockResolutionInputs, OperationOutcome, PackObjectPublication, ProcessFacts, ProgressEvent,
    ProgressSink, SecureRandomPort, StoreAccess,
};
use malm_pack::{
    GitObjectId, GitSourceV1, GitUrl, PackFileV1, PackPath, PackSubdir, pack_content_digest,
};
use malm_types::Digest;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use malm_types::{ArtifactId, DeploymentName, NamespaceName, PreparedId};

const MINIMAL_PACK: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/pack/v1/fixtures/valid/minimal.kdl"
));

#[derive(Default)]
struct FixedRandom {
    requests: Mutex<Vec<usize>>,
}

impl SecureRandomPort for FixedRandom {
    fn fill(&self, output: &mut [u8]) -> io::Result<()> {
        self.requests.lock().unwrap().push(output.len());
        output.fill(0x5a);
        Ok(())
    }
}

struct FakeGit {
    files: Vec<GitPackFile>,
    stages: Mutex<Vec<GitCommandStage>>,
}

impl FakeGit {
    fn new(files: Vec<GitPackFile>) -> Self {
        Self {
            files,
            stages: Mutex::new(Vec::new()),
        }
    }
}

impl GitProcessPort for FakeGit {
    fn initialize(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        object_format: GitObjectFormat,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        assert_eq!(object_format, GitObjectFormat::Sha1);
        self.stages
            .lock()
            .unwrap()
            .push(GitCommandStage::Initialize);
        Ok(())
    }

    fn fetch(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        url: &str,
        object_id: &str,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        assert_eq!(url, "https://example.invalid/repository.git");
        assert_eq!(object_id, "1111111111111111111111111111111111111111");
        self.stages.lock().unwrap().push(GitCommandStage::Fetch);
        Ok(())
    }

    fn read_pack(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        object_format: GitObjectFormat,
        object_id: &str,
        subdir: &str,
    ) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
        assert_eq!(object_format, GitObjectFormat::Sha1);
        assert_eq!(object_id, "1111111111111111111111111111111111111111");
        assert_eq!(subdir, ".");
        self.stages
            .lock()
            .unwrap()
            .push(GitCommandStage::ReadObjects);
        Ok(self.files.clone())
    }
}

#[derive(Default)]
struct DenyGit {
    calls: AtomicUsize,
}

impl DenyGit {
    fn deny(&self) -> ! {
        self.calls.fetch_add(1, Ordering::Relaxed);
        panic!("denied Git/network capability was invoked")
    }
}

impl GitProcessPort for DenyGit {
    fn initialize(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _object_format: GitObjectFormat,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        self.deny()
    }

    fn fetch(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _url: &str,
        _object_id: &str,
        _output_limit: u64,
    ) -> Result<(), GitAcquisitionIssue> {
        self.deny()
    }

    fn read_pack(
        &self,
        _config: &GitAcquisitionConfig,
        _scratch: &File,
        _object_format: GitObjectFormat,
        _object_id: &str,
        _subdir: &str,
    ) -> Result<Vec<GitPackFile>, GitAcquisitionIssue> {
        self.deny()
    }
}

#[derive(Default)]
struct RecordingSink {
    progress: Mutex<Vec<ProgressEvent>>,
    diagnostics: Mutex<Vec<(EngineOperation, EngineFailureKind)>>,
}

struct PanicOnDrop;

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        panic!("panic payload was dropped");
    }
}

struct PanickingProgressSink;

impl ProgressSink for PanickingProgressSink {
    fn emit(&self, _event: ProgressEvent) {
        std::panic::panic_any(PanicOnDrop);
    }
}

impl ProgressSink for RecordingSink {
    fn emit(&self, event: ProgressEvent) {
        self.progress.lock().unwrap().push(event);
    }
}

impl DiagnosticSink for RecordingSink {
    fn emit(&self, event: DiagnosticEvent<'_>) {
        self.diagnostics
            .lock()
            .unwrap()
            .push((event.operation(), event.failure().kind()));
    }
}

fn process_facts(state_home: &Path) -> ProcessFacts {
    ProcessFacts::new(fs::metadata(state_home).unwrap().uid(), Some(4_096))
}

fn engine_ports(
    facts: ProcessFacts,
    random: Arc<FixedRandom>,
    git: Arc<dyn GitProcessPort>,
    sink: Arc<RecordingSink>,
) -> EnginePorts {
    EnginePorts::new(facts, random, git, sink.clone(), sink)
}

fn exact_source() -> GitSourceV1 {
    GitSourceV1::new(
        GitUrl::new("https://example.invalid/repository.git").unwrap(),
        GitObjectId::new(format!("sha1-{}", "1".repeat(40))).unwrap(),
        PackSubdir::new(".").unwrap(),
    )
}

fn initialized_fake_engine(
    state_home: &Path,
    git: Arc<dyn GitProcessPort>,
    sink: Arc<RecordingSink>,
) -> Engine {
    let engine = Engine::new(
        EngineConfig::from_state_home(state_home, StoreAccess::ReadWrite).unwrap(),
        engine_ports(
            process_facts(state_home),
            Arc::new(FixedRandom::default()),
            git,
            sink,
        ),
    );
    engine.initialize_store().unwrap();
    engine
}

fn publish_minimal_git_pack(state_home: &Path, scratch: &Path) -> Digest {
    let files = [PackFileV1::new(
        PackPath::new("malm-pack.kdl").unwrap(),
        MINIMAL_PACK,
    )];
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let fake_git = Arc::new(FakeGit::new(
        files
            .iter()
            .map(|file| GitPackFile::new(file.path().as_str(), file.bytes()))
            .collect(),
    ));
    let engine = initialized_fake_engine(state_home, fake_git, Arc::new(RecordingSink::default()));
    engine
        .acquire_and_publish_git_pack_v1(
            &exact_source(),
            &digest,
            &GitAcquisitionConfig::new("/not-used/git").unwrap(),
            scratch,
        )
        .unwrap();
    digest
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn install_socket_kill_filter() -> io::Result<()> {
    const BPF_LOAD_WORD_ABSOLUTE: u16 = 0x20;
    const BPF_JUMP_EQUAL: u16 = 0x15;
    const BPF_RETURN: u16 = 0x06;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_RETURN_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RETURN_KILL_PROCESS: u32 = 0x8000_0000;

    let mut filters = [
        libc::sock_filter {
            code: BPF_LOAD_WORD_ABSOLUTE,
            jt: 0,
            jf: 0,
            k: u32::try_from(std::mem::offset_of!(libc::seccomp_data, arch)).unwrap(),
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
            k: u32::try_from(std::mem::offset_of!(libc::seccomp_data, nr)).unwrap(),
        },
        libc::sock_filter {
            code: BPF_JUMP_EQUAL,
            jt: 0,
            jf: 1,
            k: libc::SYS_socket as u32,
        },
        libc::sock_filter {
            code: BPF_RETURN,
            jt: 0,
            jf: 0,
            k: SECCOMP_RETURN_KILL_PROCESS,
        },
        libc::sock_filter {
            code: BPF_RETURN,
            jt: 0,
            jf: 0,
            k: SECCOMP_RETURN_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: u16::try_from(filters.len()).unwrap(),
        filter: filters.as_mut_ptr(),
    };

    // SAFETY: both prctl calls use their documented scalar arguments, and the
    // filter program remains live until installation completes.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
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

#[test]
fn engine_embeds_with_fake_ports_and_denied_network_capability() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Engine>();

    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let facts = process_facts(&state_home);
    let files = [PackFileV1::new(
        PackPath::new("malm-pack.kdl").unwrap(),
        MINIMAL_PACK,
    )];
    let digest = pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap();
    let random = Arc::new(FixedRandom::default());
    let fake_git = Arc::new(FakeGit::new(
        files
            .iter()
            .map(|file| GitPackFile::new(file.path().as_str(), file.bytes()))
            .collect(),
    ));
    let sink = Arc::new(RecordingSink::default());
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        engine_ports(facts, random.clone(), fake_git.clone(), sink.clone()),
    );

    engine.initialize_store().unwrap();
    let scratch = temp.path().join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    let git_config = GitAcquisitionConfig::new("/not-used/git").unwrap();
    assert_eq!(
        engine
            .acquire_and_publish_git_pack_v1(&exact_source(), &digest, &git_config, &scratch,)
            .unwrap(),
        PackObjectPublication::Published
    );
    assert_eq!(*random.requests.lock().unwrap(), [16]);
    assert_eq!(
        *fake_git.stages.lock().unwrap(),
        [
            GitCommandStage::Initialize,
            GitCommandStage::Fetch,
            GitCommandStage::ReadObjects,
        ]
    );
    assert!(sink.diagnostics.lock().unwrap().is_empty());

    let denied = Arc::new(DenyGit::default());
    let denied_sink = Arc::new(RecordingSink::default());
    let offline = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        engine_ports(
            facts,
            Arc::new(FixedRandom::default()),
            denied.clone(),
            denied_sink.clone(),
        ),
    );
    assert_eq!(
        offline
            .acquire_and_publish_git_pack_v1(
                &exact_source(),
                &digest,
                &git_config,
                Path::new("/missing/scratch"),
            )
            .unwrap(),
        PackObjectPublication::Reused
    );
    assert_eq!(denied.calls.load(Ordering::Relaxed), 0);

    let progress = denied_sink.progress.lock().unwrap();
    assert!(matches!(
        progress.as_slice(),
        [
            ProgressEvent::OperationStarted {
                operation: EngineOperation::AcquireGitPackV1,
                ..
            },
            ProgressEvent::OperationFinished {
                operation: EngineOperation::AcquireGitPackV1,
                outcome: OperationOutcome::Succeeded,
                ..
            }
        ]
    ));
}

#[test]
fn failed_operation_emits_one_typed_diagnostic() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let sink = Arc::new(RecordingSink::default());
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadOnly).unwrap(),
        engine_ports(
            process_facts(&state_home),
            Arc::new(FixedRandom::default()),
            Arc::new(DenyGit::default()),
            sink.clone(),
        ),
    );

    assert!(engine.initialize_store().is_err());
    assert_eq!(
        *sink.diagnostics.lock().unwrap(),
        [(EngineOperation::InitializeStore, EngineFailureKind::Engine)]
    );
    assert!(matches!(
        sink.progress.lock().unwrap().as_slice(),
        [
            ProgressEvent::OperationStarted {
                operation: EngineOperation::InitializeStore,
                ..
            },
            ProgressEvent::OperationFinished {
                operation: EngineOperation::InitializeStore,
                outcome: OperationOutcome::Failed,
                ..
            }
        ]
    ));
}

#[test]
fn fake_process_facts_control_identity_and_descriptor_limits() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let actual_facts = process_facts(&state_home);
    let random = Arc::new(FixedRandom::default());
    let wrong_identity = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        engine_ports(
            ProcessFacts::new(
                actual_facts.effective_user_id().wrapping_add(1),
                Some(4_096),
            ),
            random.clone(),
            Arc::new(DenyGit::default()),
            Arc::new(RecordingSink::default()),
        ),
    );
    assert!(matches!(
        wrong_identity.initialize_store(),
        Err(EngineError::UnsafeDirectory {
            reason: DirectorySafetyIssue::WrongOwner { .. },
            ..
        })
    ));
    assert!(random.requests.lock().unwrap().is_empty());

    let initializer = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        engine_ports(
            actual_facts,
            Arc::new(FixedRandom::default()),
            Arc::new(DenyGit::default()),
            Arc::new(RecordingSink::default()),
        ),
    );
    initializer.initialize_store().unwrap();
    let root_pack = temp.path().join("root-pack");
    fs::create_dir(&root_pack).unwrap();
    fs::write(root_pack.join("malm-pack.kdl"), MINIMAL_PACK).unwrap();

    let denied = Arc::new(DenyGit::default());
    let constrained = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        engine_ports(
            ProcessFacts::new(actual_facts.effective_user_id(), Some(1)),
            Arc::new(FixedRandom::default()),
            denied.clone(),
            Arc::new(RecordingSink::default()),
        ),
    );
    let inputs = LockResolutionInputs::new(BTreeSet::new(), BTreeSet::new(), BTreeMap::new());
    assert!(matches!(
        constrained.create_lock_v1(
            &root_pack,
            &inputs,
            &GitAcquisitionConfig::new("/not-used/git").unwrap(),
        ),
        Err(LockOperationError::ResourceLimitExceeded {
            resource: "pinned source descriptors",
            limit: 0,
            ..
        })
    ));
    assert!(!root_pack.join("malm.lock").exists());
    assert_eq!(denied.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn malformed_git_port_output_is_rejected_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let malformed = Arc::new(FakeGit::new(vec![GitPackFile::new(
        "../malm-pack.kdl",
        MINIMAL_PACK,
    )]));
    let engine =
        initialized_fake_engine(&state_home, malformed, Arc::new(RecordingSink::default()));
    let scratch = temp.path().join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();

    let error = engine
        .acquire_and_publish_git_pack_v1(
            &exact_source(),
            &Digest::sha256(b"unpublished"),
            &GitAcquisitionConfig::new("/not-used/git").unwrap(),
            &scratch,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        EngineError::GitAcquisition {
            reason: GitAcquisitionIssue::InvalidPath { .. },
            ..
        }
    ));
    assert!(!engine.config().state_root().join("objects/packs").exists());
}

#[test]
fn lock_creation_emits_only_its_top_level_event_pair() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let sink = Arc::new(RecordingSink::default());
    let fake_git = Arc::new(FakeGit::new(vec![GitPackFile::new(
        "malm-pack.kdl",
        MINIMAL_PACK,
    )]));
    let engine = initialized_fake_engine(&state_home, fake_git, sink.clone());
    sink.progress.lock().unwrap().clear();

    let root_pack = temp.path().join("root-pack");
    fs::create_dir(&root_pack).unwrap();
    fs::write(
        root_pack.join("malm-pack.kdl"),
        b"pack schema-version=1 package-id=\"com.example.root\" {\n\
          modules {\n}\n\
          config-documents {\n}\n\
          dependencies {\n\
            dependency \"remote\" package-id=\"com.example.minimal\" {\n\
              git url=\"https://example.invalid/repository.git\" commit=\"sha1-1111111111111111111111111111111111111111\" subdir=\".\"\n\
            }\n\
          }\n\
          templates {\n}\n\
          schemas {\n}\n\
          assets {\n}\n\
          components {\n}\n\
        }\n",
    )
    .unwrap();
    let scratch = temp.path().join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    let source = exact_source();
    let inputs = LockResolutionInputs::new(
        BTreeSet::new(),
        BTreeSet::from([source.url().clone()]),
        BTreeMap::from([(source, scratch)]),
    );
    engine
        .create_lock_v1(
            &root_pack,
            &inputs,
            &GitAcquisitionConfig::new("/not-used/git").unwrap(),
        )
        .unwrap();

    assert!(sink.diagnostics.lock().unwrap().is_empty());
    assert!(matches!(
        sink.progress.lock().unwrap().as_slice(),
        [
            ProgressEvent::OperationStarted {
                operation: EngineOperation::CreateLockV1,
                ..
            },
            ProgressEvent::OperationFinished {
                operation: EngineOperation::CreateLockV1,
                outcome: OperationOutcome::Succeeded,
                ..
            }
        ]
    ));
}

#[test]
fn system_capabilities_can_be_retained_while_observers_are_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let sink = Arc::new(RecordingSink::default());
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        EnginePorts::system().with_sinks(sink.clone(), sink.clone()),
    );

    engine.initialize_store().unwrap();
    assert!(matches!(
        sink.progress.lock().unwrap().as_slice(),
        [
            ProgressEvent::OperationStarted {
                operation: EngineOperation::InitializeStore,
                ..
            },
            ProgressEvent::OperationFinished {
                operation: EngineOperation::InitializeStore,
                outcome: OperationOutcome::Succeeded,
                ..
            }
        ]
    ));
}

#[test]
fn observer_panics_and_panicking_payload_drops_cannot_replace_results() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        EnginePorts::new(
            process_facts(&state_home),
            Arc::new(FixedRandom::default()),
            Arc::new(DenyGit::default()),
            Arc::new(PanickingProgressSink),
            Arc::new(RecordingSink::default()),
        ),
    );

    engine.initialize_store().unwrap();
}

#[test]
fn corrupt_cached_object_fails_without_invoking_git() {
    let temp = tempfile::tempdir().unwrap();
    let state_home = temp.path().join("state");
    fs::create_dir(&state_home).unwrap();
    fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = temp.path().join("scratch");
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    let digest = publish_minimal_git_pack(&state_home, &scratch);
    let object = state_home
        .join("malm/objects/pack-manifests")
        .join(digest.as_str());
    fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&object, b"corrupt\n").unwrap();
    fs::set_permissions(&object, fs::Permissions::from_mode(0o400)).unwrap();

    let denied = Arc::new(DenyGit::default());
    let engine = Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        engine_ports(
            process_facts(&state_home),
            Arc::new(FixedRandom::default()),
            denied.clone(),
            Arc::new(RecordingSink::default()),
        ),
    );
    let error = engine
        .acquire_and_publish_git_pack_v1(
            &exact_source(),
            &digest,
            &GitAcquisitionConfig::new("/not-used/git").unwrap(),
            Path::new("/missing/scratch"),
        )
        .unwrap_err();
    assert!(matches!(error, EngineError::PackObject { .. }));
    assert_eq!(denied.calls.load(Ordering::Relaxed), 0);
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn verified_cache_reuse_succeeds_under_a_socket_kill_filter() {
    const CHILD_MODE: &str = "MALM_SOCKET_FILTER_CHILD";
    const STATE_HOME: &str = "MALM_SOCKET_FILTER_STATE_HOME";
    const DIGEST: &str = "MALM_SOCKET_FILTER_DIGEST";

    match std::env::var(CHILD_MODE).as_deref() {
        Ok("probe") => {
            install_socket_kill_filter().unwrap();
            // SAFETY: this canary syscall has no live Rust resources and must
            // terminate the disposable child if the filter is effective.
            let _ = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            panic!("socket kill filter did not terminate its canary child");
        }
        Ok("reuse") => {
            let state_home = std::path::PathBuf::from(std::env::var_os(STATE_HOME).unwrap());
            let digest = Digest::new(std::env::var(DIGEST).unwrap()).unwrap();
            install_socket_kill_filter().unwrap();
            let denied = Arc::new(DenyGit::default());
            let engine = Engine::new(
                EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
                engine_ports(
                    process_facts(&state_home),
                    Arc::new(FixedRandom::default()),
                    denied.clone(),
                    Arc::new(RecordingSink::default()),
                ),
            );
            assert_eq!(
                engine
                    .acquire_and_publish_git_pack_v1(
                        &exact_source(),
                        &digest,
                        &GitAcquisitionConfig::new("/not-used/git").unwrap(),
                        Path::new("/missing/scratch"),
                    )
                    .unwrap(),
                PackObjectPublication::Reused
            );
            assert_eq!(denied.calls.load(Ordering::Relaxed), 0);
        }
        Ok(mode) => panic!("unexpected socket-filter child mode {mode}"),
        Err(_) => {
            let executable = std::env::current_exe().unwrap();
            let probe = Command::new(&executable)
                .args([
                    "--exact",
                    "verified_cache_reuse_succeeds_under_a_socket_kill_filter",
                    "--nocapture",
                ])
                .env(CHILD_MODE, "probe")
                .output()
                .unwrap();
            assert_eq!(
                probe.status.signal(),
                Some(libc::SIGSYS),
                "socket filter canary was not killed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&probe.stdout),
                String::from_utf8_lossy(&probe.stderr)
            );

            let temp = tempfile::tempdir().unwrap();
            let state_home = temp.path().join("state");
            fs::create_dir(&state_home).unwrap();
            fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
            let scratch = temp.path().join("scratch");
            fs::create_dir(&scratch).unwrap();
            fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
            let digest = publish_minimal_git_pack(&state_home, &scratch);
            let reuse = Command::new(executable)
                .args([
                    "--exact",
                    "verified_cache_reuse_succeeds_under_a_socket_kill_filter",
                    "--nocapture",
                ])
                .env(CHILD_MODE, "reuse")
                .env(STATE_HOME, &state_home)
                .env(DIGEST, digest.as_str())
                .output()
                .unwrap();
            assert!(
                reuse.status.success(),
                "cache-reuse child failed under denied network:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&reuse.stdout),
                String::from_utf8_lossy(&reuse.stderr)
            );
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn commit_publishes_target_and_state_under_a_socket_kill_filter() {
    const CHILD_MODE: &str = "MALM_COMMIT_SOCKET_FILTER_CHILD";
    const STATE_HOME: &str = "MALM_COMMIT_SOCKET_FILTER_STATE_HOME";
    const TARGET: &str = "MALM_COMMIT_SOCKET_FILTER_TARGET";
    const PLAN_ID: &str = "MALM_COMMIT_SOCKET_FILTER_PLAN_ID";
    const TEST_NAME: &str = "commit_publishes_target_and_state_under_a_socket_kill_filter";
    const TARGET_BYTES: &[u8] = b"committed without network\n";

    match std::env::var(CHILD_MODE).as_deref() {
        Ok("probe") => {
            install_socket_kill_filter().unwrap();
            // SAFETY: this canary syscall has no live Rust resources and must
            // terminate the disposable child if the filter is effective.
            let _ = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            panic!("socket kill filter did not terminate its canary child");
        }
        Ok("commit") => {
            let state_home = std::path::PathBuf::from(std::env::var_os(STATE_HOME).unwrap());
            let target = std::path::PathBuf::from(std::env::var_os(TARGET).unwrap());
            let plan_id = PreparedId::new(std::env::var(PLAN_ID).unwrap()).unwrap();
            install_socket_kill_filter().unwrap();

            let denied = Arc::new(DenyGit::default());
            let sink = Arc::new(RecordingSink::default());
            let engine = Engine::new(
                EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
                    .unwrap()
                    .with_target_authority(DeploymentName::new("home").unwrap(), &target)
                    .unwrap(),
                engine_ports(
                    process_facts(&state_home),
                    Arc::new(FixedRandom::default()),
                    denied.clone(),
                    sink,
                ),
            );
            let durable_plan = engine.plan_v1(&plan_id).unwrap();
            let outcome = engine
                .commit_v1(&CommitRequestV1::new(
                    plan_id.clone(),
                    ApprovalV1::new(plan_id.clone(), durable_plan.approval_digest().clone()),
                ))
                .unwrap();

            assert_eq!(outcome.plan_id(), &plan_id);
            assert!(outcome.previous_head().is_none());
            let published = target.join("config/offline.conf");
            assert_eq!(fs::read(&published).unwrap(), TARGET_BYTES);
            assert_eq!(
                fs::metadata(&published).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                engine
                    .inspect_state_v1(durable_plan.namespace())
                    .unwrap()
                    .head(),
                Some(outcome.head())
            );
            assert_eq!(denied.calls.load(Ordering::Relaxed), 0);
        }
        Ok(mode) => panic!("unexpected commit socket-filter child mode {mode}"),
        Err(_) => {
            let temp = tempfile::tempdir().unwrap();
            let state_home = temp.path().join("state");
            fs::create_dir(&state_home).unwrap();
            fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
            let target = temp.path().join("target");
            fs::create_dir(&target).unwrap();
            fs::create_dir(target.join("config")).unwrap();

            let denied = Arc::new(DenyGit::default());
            let sink = Arc::new(RecordingSink::default());
            let engine = Engine::new(
                EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite)
                    .unwrap()
                    .with_target_authority(DeploymentName::new("home").unwrap(), &target)
                    .unwrap(),
                engine_ports(
                    process_facts(&state_home),
                    Arc::new(FixedRandom::default()),
                    denied.clone(),
                    sink,
                ),
            );
            engine.initialize_store().unwrap();
            let artifact_id = ArtifactId::new("config/offline").unwrap();
            let prepared = engine
                .prepare_v1(&PrepareRequestV1::from(PrepareRequestPartsV1 {
                    namespace: NamespaceName::new("offline-commit").unwrap(),
                    expected_head: None,
                    graph_digest: Digest::sha256(b"offline commit graph"),
                    inputs: vec![],
                    artifacts: vec![
                        PrepareArtifactV1::new(
                            artifact_id.clone(),
                            TARGET_BYTES.to_vec(),
                            "text/plain",
                        )
                        .unwrap(),
                    ],
                    transforms: vec![],
                    findings: vec![],
                    operations: vec![
                        PrepareOperationV1::place_file(
                            DeploymentName::new("home").unwrap(),
                            "config/offline.conf",
                            artifact_id,
                            0o600,
                        )
                        .unwrap(),
                    ],
                }))
                .unwrap();
            assert_eq!(prepared.operation_count(), 1);
            assert_eq!(engine.plan_v1(prepared.plan_id()).unwrap(), prepared);
            assert_eq!(denied.calls.load(Ordering::Relaxed), 0);
            assert!(!target.join("config/offline.conf").exists());
            assert!(
                engine
                    .inspect_state_v1(prepared.namespace())
                    .unwrap()
                    .head()
                    .is_none()
            );
            drop(engine);

            let executable = std::env::current_exe().unwrap();
            let probe = Command::new(&executable)
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_MODE, "probe")
                .output()
                .unwrap();
            assert_eq!(
                probe.status.signal(),
                Some(libc::SIGSYS),
                "socket filter canary was not killed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&probe.stdout),
                String::from_utf8_lossy(&probe.stderr)
            );

            let commit = Command::new(executable)
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_MODE, "commit")
                .env(STATE_HOME, &state_home)
                .env(TARGET, &target)
                .env(PLAN_ID, prepared.plan_id().as_str())
                .output()
                .unwrap();
            assert!(
                commit.status.success(),
                "commit child failed under denied network:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&commit.stdout),
                String::from_utf8_lossy(&commit.stderr)
            );
        }
    }
}
