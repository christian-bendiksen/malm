#![cfg(all(target_os = "linux", feature = "failpoints"))]

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use malm::{
    ApprovalV1, ArtifactBytesInspectionRequestV1, ArtifactMetadataInspectionRequestV1,
    CatalogInspectionRequestV1, CommitRequestV1, DesiredSnapshotInspectionRequestV1, Engine,
    EngineConfig, EnginePorts, FsckRequestV1, GenerationInspectionRequestV1,
    NamespaceHistoryRequestV1, NamespaceInspectionRequestV1, NamespaceStatusRequestV1,
    PrepareArtifactV1, PrepareOperationV1, PrepareRequestPartsV1, PrepareRequestV1,
    PreparedPlanInspectionRequestV1, StoreAccess,
};
use malm_types::{ArtifactId, DeploymentName, Digest, NamespaceName};

const CHILD_MODE: &str = "MALM_V1_SYSCALL_TRACE_CHILD";
const CHILD_ROOT: &str = "MALM_V1_SYSCALL_TRACE_ROOT";
const REPLACED_PATH: &str = "config/replaced.conf";
const REMOVED_PATH: &str = "config/removed.conf";
const ORIGINAL_REPLACED: &[u8] = b"original replacement target\n";
const ORIGINAL_REMOVED: &[u8] = b"original removal target\n";
const PREPARED_REPLACEMENT: &[u8] = b"prepared replacement target\n";
const TRACE_SYSCALLS: &str = concat!(
    "open,openat,openat2,creat,",
    "write,writev,pwrite64,pwritev,pwritev2,copy_file_range,sendfile,splice,",
    "stat,lstat,fstat,newfstatat,statx,statfs,fstatfs,",
    "access,faccessat,faccessat2,readlink,readlinkat,chdir,fchdir,",
    "mkdir,mkdirat,link,linkat,rename,renameat,renameat2,",
    "unlink,unlinkat,rmdir,symlink,symlinkat,mknod,mknodat,",
    "chmod,fchmod,fchmodat,fchmodat2,chown,fchown,fchownat,lchown,",
    "truncate,ftruncate,fallocate,utime,utimes,futimesat,utimensat,",
    "getxattr,lgetxattr,fgetxattr,listxattr,llistxattr,flistxattr,",
    "setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,",
    "flock,fsync,fdatasync,syncfs"
);

struct Roots {
    state_parent: PathBuf,
    state: PathBuf,
    experimental: PathBuf,
    target: PathBuf,
}

impl Roots {
    fn at(root: &Path) -> Self {
        let state_parent = root.join("state");
        Self {
            state: state_parent.join("malm"),
            experimental: state_parent.join("malm-v1"),
            target: root.join("target"),
            state_parent,
        }
    }
}

fn create_fixture() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    let roots = Roots::at(temp.path());
    create_directory(&roots.state_parent, 0o700);
    create_directory(&roots.experimental, 0o700);
    create_directory(&roots.experimental.join("transactions"), 0o700);
    write_file(
        &roots.experimental.join("transactions/sentinel"),
        b"protected experimental state\n",
        0o600,
    );
    fs::set_permissions(&roots.experimental, fs::Permissions::from_mode(0o000)).unwrap();
    create_directory(&roots.target, 0o700);
    create_directory(&roots.target.join("config"), 0o700);
    temp
}

fn create_directory(path: &Path, mode: u32) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn make_engine(root: &Path) -> Engine {
    make_engine_with_access(root, StoreAccess::ReadWrite)
}

fn make_engine_with_access(root: &Path, access: StoreAccess) -> Engine {
    let roots = Roots::at(root);
    Engine::new(
        EngineConfig::from_state_home(&roots.state_parent, access)
            .unwrap()
            .with_target_authority(DeploymentName::new("home").unwrap(), roots.target)
            .unwrap(),
        EnginePorts::system(),
    )
}

fn baseline_request() -> PrepareRequestV1 {
    let replaced = ArtifactId::new("config/original-replaced").unwrap();
    let removed = ArtifactId::new("config/original-removed").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: None,
        graph_digest: Digest::sha256(b"syscall trace baseline"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(replaced.clone(), ORIGINAL_REPLACED.to_vec(), "text/plain")
                .unwrap(),
            PrepareArtifactV1::new(removed.clone(), ORIGINAL_REMOVED.to_vec(), "text/plain")
                .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                REPLACED_PATH,
                replaced,
                0o600,
            )
            .unwrap(),
            PrepareOperationV1::place_file(
                DeploymentName::new("home").unwrap(),
                REMOVED_PATH,
                removed,
                0o600,
            )
            .unwrap(),
        ],
    })
}

fn seed_owned_targets(engine: &Engine) -> malm::ApplyOutcomeV1 {
    let prepared = engine.prepare_v1(&baseline_request()).unwrap();
    engine.commit_v1(&commit_request(&prepared)).unwrap()
}

fn replacement_and_removal_request(expected_head: Digest) -> PrepareRequestV1 {
    let artifact = ArtifactId::new("config/replacement").unwrap();
    PrepareRequestV1::from(PrepareRequestPartsV1 {
        namespace: NamespaceName::new("workstation").unwrap(),
        expected_head: Some(expected_head),
        graph_digest: Digest::sha256(b"syscall trace replacement and removal"),
        inputs: vec![],
        artifacts: vec![
            PrepareArtifactV1::new(
                artifact.clone(),
                PREPARED_REPLACEMENT.to_vec(),
                "text/plain",
            )
            .unwrap(),
        ],
        transforms: vec![],
        findings: vec![],
        operations: vec![
            PrepareOperationV1::replace_file(
                DeploymentName::new("home").unwrap(),
                REPLACED_PATH,
                artifact,
                0o600,
            )
            .unwrap(),
            PrepareOperationV1::remove_leaf(DeploymentName::new("home").unwrap(), REMOVED_PATH)
                .unwrap(),
        ],
    })
}

fn commit_request(prepared: &malm::PreparedDeploymentV1) -> CommitRequestV1 {
    CommitRequestV1::new(
        prepared.plan_id().clone(),
        ApprovalV1::new(
            prepared.plan_id().clone(),
            prepared.approval_digest().clone(),
        ),
    )
}

#[test]
fn syscall_trace_child() {
    let Some(mode) = std::env::var_os(CHILD_MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("trace child root"));
    let engine = make_engine(&root);

    match mode.to_str().expect("UTF-8 child mode") {
        "lifecycle" => {
            engine.initialize_store().unwrap();
            let baseline = seed_owned_targets(&engine);
            let prepared = engine
                .prepare_v1(&replacement_and_removal_request(baseline.head().clone()))
                .unwrap();
            engine.commit_v1(&commit_request(&prepared)).unwrap();
        }
        "crash" => {
            engine.initialize_store().unwrap();
            let baseline = seed_owned_targets(&engine);
            let prepared = engine
                .prepare_v1(&replacement_and_removal_request(baseline.head().clone()))
                .unwrap();
            engine.commit_v1(&commit_request(&prepared)).unwrap();
            panic!("configured commit failpoint did not fire");
        }
        "recover" => {
            assert!(engine.recover_v1().unwrap().head().is_some());
        }
        "inspection" => {
            let engine = make_engine_with_access(&root, StoreAccess::ReadOnly);
            let namespace = NamespaceName::new("workstation").unwrap();
            let catalog = engine
                .inspect_catalog_v1(&CatalogInspectionRequestV1::new())
                .unwrap();
            assert_eq!(catalog.namespaces().len(), 1);
            let selected = engine
                .inspect_namespace_v1(&NamespaceInspectionRequestV1::new(namespace.clone()))
                .unwrap();
            let head = selected.head().unwrap().clone();
            let history = engine
                .inspect_namespace_history_v1(&NamespaceHistoryRequestV1::new(namespace.clone()))
                .unwrap();
            assert_eq!(history.head(), Some(&head));
            let generation_request =
                GenerationInspectionRequestV1::new(namespace.clone(), head.clone());
            let generation = engine
                .inspect_generation_details_v1(&generation_request)
                .unwrap();
            let snapshot = engine
                .inspect_desired_snapshot_v1(&DesiredSnapshotInspectionRequestV1::new(
                    namespace.clone(),
                    head,
                ))
                .unwrap();
            assert_eq!(snapshot.targets().len(), 2);
            let plan_request = PreparedPlanInspectionRequestV1::new(generation.plan_id().clone());
            let plan = engine.inspect_prepared_plan_v1(&plan_request).unwrap();
            let artifact = plan.artifacts().first().unwrap();
            engine
                .inspect_artifact_metadata_v1(&ArtifactMetadataInspectionRequestV1::new(
                    plan.plan_id().clone(),
                    artifact.id().clone(),
                ))
                .unwrap();
            engine
                .inspect_artifact_bytes_v1(&ArtifactBytesInspectionRequestV1::new(
                    plan.plan_id().clone(),
                    artifact.id().clone(),
                ))
                .unwrap();
            engine.inspect_captured_inputs_v1(&plan_request).unwrap();
            engine
                .inspect_transform_provenance_v1(&plan_request)
                .unwrap();
            engine
                .inspect_retention_authority_v1(&generation_request)
                .unwrap();
            engine.inspect_tracking_v1(&generation_request).unwrap();
            engine
                .inspect_namespace_status_v1(&NamespaceStatusRequestV1::new(namespace))
                .unwrap();
            assert!(engine.fsck_v1(&FsckRequestV1::new()).unwrap().is_clean());
        }
        other => panic!("unknown syscall trace child mode {other:?}"),
    }
}

#[test]
fn syscall_trace_fixture_establishes_ownership_before_destructive_operations() {
    let fixture = create_fixture();
    let roots = Roots::at(fixture.path());
    let engine = make_engine(fixture.path());
    engine.initialize_store().unwrap();
    let baseline = seed_owned_targets(&engine);
    let prepared = engine
        .prepare_v1(&replacement_and_removal_request(baseline.head().clone()))
        .unwrap();

    engine.commit_v1(&commit_request(&prepared)).unwrap();

    assert_eq!(
        fs::read(roots.target.join(REPLACED_PATH)).unwrap(),
        PREPARED_REPLACEMENT
    );
    assert!(!roots.target.join(REMOVED_PATH).exists());
}

#[derive(Debug)]
struct TraceCall {
    pid: Option<u32>,
    line_number: usize,
    name: String,
    args: Vec<String>,
    result: String,
    raw: String,
}

impl TraceCall {
    fn succeeded(&self) -> bool {
        self.result
            .strip_prefix("= ")
            .is_some_and(|result| !result.starts_with("-1") && !result.starts_with('?'))
    }
}

struct Trace {
    label: &'static str,
    path: PathBuf,
    raw: String,
    calls: Vec<TraceCall>,
}

fn parse_trace(raw: &str) -> Result<Vec<TraceCall>, String> {
    struct PendingCall {
        line_number: usize,
        name: String,
        body: String,
        raw: String,
    }

    let mut calls = Vec::new();
    let mut pending = BTreeMap::<Option<u32>, PendingCall>::new();
    for (offset, raw_line) in raw.lines().enumerate() {
        let line_number = offset + 1;
        let (pid, body) = strip_trace_prefix(raw_line);
        let body = body.trim_end();
        if let Some(prefix) = body.strip_suffix("<unfinished ...>") {
            let name = syscall_name(prefix).ok_or_else(|| {
                format!("line {line_number} has an unrecognized unfinished syscall: {raw_line}")
            })?;
            if pending
                .insert(
                    pid,
                    PendingCall {
                        line_number,
                        name: name.to_owned(),
                        body: prefix.to_owned(),
                        raw: raw_line.to_owned(),
                    },
                )
                .is_some()
            {
                return Err(format!(
                    "line {line_number} starts a second unfinished syscall for pid {pid:?}"
                ));
            }
            continue;
        }
        if let Some(resumed) = body.strip_prefix("<... ") {
            let Some((name, suffix)) = resumed.split_once(" resumed>") else {
                return Err(format!(
                    "line {line_number} has malformed resumed output: {raw_line}"
                ));
            };
            let Some(started) = pending.remove(&pid) else {
                return Err(format!(
                    "line {line_number} resumes {name} without an unfinished call for pid {pid:?}"
                ));
            };
            if name != started.name {
                return Err(format!(
                    "line {line_number} resumes {name}, but {} was unfinished for pid {pid:?}",
                    started.name
                ));
            }
            let combined = format!("{}{}", started.body, suffix);
            let combined_raw = format!("{}\n{raw_line}", started.raw);
            calls.push(parse_call_body(
                pid,
                started.line_number,
                &combined,
                combined_raw,
            )?);
            continue;
        }
        if syscall_name(body).is_some() {
            calls.push(parse_call_body(
                pid,
                line_number,
                body,
                raw_line.to_owned(),
            )?);
        }
    }
    if !pending.is_empty() {
        return Err(format!(
            "trace ended with {} unfinished syscall(s)",
            pending.len()
        ));
    }
    if calls.is_empty() {
        return Err("trace contained no focused syscall records".to_owned());
    }
    if !calls.iter().any(|call| {
        call.args.iter().any(|argument| fd_path(argument).is_some())
            || fd_path(&call.result).is_some()
    }) {
        return Err("strace -yy output did not include descriptor path annotations".to_owned());
    }
    Ok(calls)
}

fn strip_trace_prefix(line: &str) -> (Option<u32>, &str) {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix("[pid ")
        && let Some((pid, body)) = rest.split_once(']')
        && let Ok(pid) = pid.trim().parse()
    {
        return (Some(pid), body.trim_start());
    }
    let digit_count = trimmed.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count > 0
        && trimmed
            .as_bytes()
            .get(digit_count)
            .is_some_and(u8::is_ascii_whitespace)
        && let Ok(pid) = trimmed[..digit_count].parse()
    {
        return (Some(pid), trimmed[digit_count..].trim_start());
    }
    (None, trimmed)
}

fn syscall_name(body: &str) -> Option<&str> {
    let open = body.find('(')?;
    let name = body[..open].trim();
    (TRACE_SYSCALLS.split(',').any(|candidate| candidate == name)).then_some(name)
}

fn parse_call_body(
    pid: Option<u32>,
    line_number: usize,
    body: &str,
    raw: String,
) -> Result<TraceCall, String> {
    let open = body
        .find('(')
        .ok_or_else(|| format!("line {line_number} has no syscall argument list: {body}"))?;
    let result = body.rfind('=').ok_or_else(|| {
        format!("line {line_number} has unsupported syscall result formatting: {body}")
    })?;
    let call = body[..result].trim_end();
    let Some(arguments_end) = call.strip_suffix(')').map(str::len) else {
        return Err(format!(
            "line {line_number} has unsupported syscall result formatting: {body}"
        ));
    };
    if arguments_end < open {
        return Err(format!(
            "line {line_number} has malformed syscall delimiters: {body}"
        ));
    }
    let name = body[..open].trim();
    if !TRACE_SYSCALLS.split(',').any(|candidate| candidate == name) {
        return Err(format!(
            "line {line_number} names unexpected syscall {name:?}"
        ));
    }
    Ok(TraceCall {
        pid,
        line_number,
        name: name.to_owned(),
        args: split_arguments(&call[open + 1..arguments_end])?,
        result: body[result..].trim_start().to_owned(),
        raw,
    })
}

fn split_arguments(arguments: &str) -> Result<Vec<String>, String> {
    if arguments.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0_u32;
    for (index, character) in arguments.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("unbalanced syscall arguments: {arguments}"))?;
            }
            ',' if depth == 0 => {
                result.push(arguments[start..index].trim().to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || escaped || depth != 0 {
        return Err(format!("unterminated syscall arguments: {arguments}"));
    }
    result.push(arguments[start..].trim().to_owned());
    Ok(result)
}

fn fd_path(argument: &str) -> Option<PathBuf> {
    let open = argument.find('<')?;
    let close = argument.rfind('>')?;
    if close <= open + 1 {
        return None;
    }
    let path = argument[open + 1..close]
        .strip_suffix(" (deleted)")
        .unwrap_or(&argument[open + 1..close]);
    path.starts_with('/').then(|| PathBuf::from(path))
}

fn path_argument(argument: &str) -> Option<&str> {
    let argument = argument.trim();
    let path = argument.strip_prefix('"')?.strip_suffix('"')?;
    (!path.contains('\\')).then_some(path)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathArgument {
    Direct { path: usize },
    DescriptorRelative { descriptor: usize, path: usize },
}

fn path_arguments(call: &TraceCall) -> Result<Vec<PathArgument>, String> {
    use PathArgument::{DescriptorRelative as At, Direct};

    let paths = match call.name.as_str() {
        "open" | "creat" | "stat" | "lstat" | "statfs" | "access" | "readlink" | "chdir"
        | "mkdir" | "unlink" | "rmdir" | "mknod" | "chmod" | "chown" | "lchown" | "truncate"
        | "utime" | "utimes" | "getxattr" | "lgetxattr" | "listxattr" | "llistxattr"
        | "setxattr" | "lsetxattr" | "removexattr" | "lremovexattr" => vec![Direct { path: 0 }],
        "link" | "rename" => vec![Direct { path: 0 }, Direct { path: 1 }],
        // A symlink stores its first argument; the kernel does not traverse it here.
        "symlink" => vec![Direct { path: 1 }],
        "openat" | "openat2" | "newfstatat" | "statx" | "faccessat" | "faccessat2"
        | "readlinkat" | "mkdirat" | "unlinkat" | "mknodat" | "fchmodat" | "fchmodat2"
        | "fchownat" | "futimesat" | "utimensat" => {
            vec![At {
                descriptor: 0,
                path: 1,
            }]
        }
        "linkat" | "renameat" | "renameat2" => vec![
            At {
                descriptor: 0,
                path: 1,
            },
            At {
                descriptor: 2,
                path: 3,
            },
        ],
        "symlinkat" => vec![At {
            descriptor: 1,
            path: 2,
        }],
        "write" | "writev" | "pwrite64" | "pwritev" | "pwritev2" | "copy_file_range"
        | "sendfile" | "splice" | "fstat" | "fstatfs" | "fchdir" | "fgetxattr" | "flistxattr"
        | "fchmod" | "fchown" | "ftruncate" | "fallocate" | "fsetxattr" | "fremovexattr"
        | "flock" | "fsync" | "fdatasync" | "syncfs" => Vec::new(),
        other => {
            return Err(format!(
                "focused syscall {other} has no path-argument classification: {}",
                call.raw
            ));
        }
    };
    for path in &paths {
        let index = match path {
            Direct { path } | At { path, .. } => *path,
        };
        call_argument(call, index)?;
    }
    Ok(paths)
}

fn has_symbolic_flag(argument: &str, expected: &str) -> bool {
    argument
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|flag| flag == expected)
}

fn call_argument(call: &TraceCall, index: usize) -> Result<&str, String> {
    call.args.get(index).map(String::as_str).ok_or_else(|| {
        format!(
            "{} at line {} has only {} argument(s): {}",
            call.name,
            call.line_number,
            call.args.len(),
            call.raw
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Scope {
    StateParent,
    V1,
    Target,
}

#[derive(Debug)]
struct MutationUse {
    scope: Scope,
    resolved: PathBuf,
}

fn scope(path: &Path, roots: &Roots) -> Result<Scope, String> {
    if path == roots.experimental || path.starts_with(&roots.experimental) {
        return Err(format!(
            "filesystem handle or destination enters the experimental sibling {}",
            roots.experimental.display()
        ));
    }
    if path == roots.state || path.starts_with(&roots.state) {
        return Ok(Scope::V1);
    }
    if path == roots.target || path.starts_with(&roots.target) {
        return Ok(Scope::Target);
    }
    if path == roots.state_parent {
        return Ok(Scope::StateParent);
    }
    if let Ok(relative) = path.strip_prefix(&roots.state_parent)
        && relative
            .components()
            .next()
            .and_then(|component| match component {
                Component::Normal(name) => name.to_str(),
                _ => None,
            })
            .is_some_and(|name| name.starts_with(".malm.init-"))
    {
        return Ok(Scope::V1);
    }
    Err(format!(
        "mutation handle {} is outside the pinned state/target authorities",
        path.display()
    ))
}

fn descriptor_use(call: &TraceCall, fd_index: usize, roots: &Roots) -> Result<MutationUse, String> {
    let argument = call_argument(call, fd_index)?;
    let path = fd_path(argument).ok_or_else(|| {
        format!(
            "{} descriptor argument {argument:?} lacks a usable -yy path annotation",
            call.name
        )
    })?;
    Ok(MutationUse {
        scope: scope(&path, roots)?,
        resolved: path,
    })
}

fn relative_use(
    call: &TraceCall,
    fd_index: usize,
    path_index: usize,
    roots: &Roots,
) -> Result<MutationUse, String> {
    let descriptor = descriptor_use(call, fd_index, roots)?;
    let argument = call_argument(call, path_index)?;
    let relative = path_argument(argument).ok_or_else(|| {
        format!(
            "{} path argument {argument:?} is not an untruncated quoted path",
            call.name
        )
    })?;
    let relative_path = Path::new(relative);
    if relative_path.is_absolute() {
        return Err(format!(
            "{} uses absolute mutation path {relative:?}",
            call.name
        ));
    }
    let mut resolved = descriptor.resolved.clone();
    for component in relative_path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => resolved.push(component),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "{} mutation path {relative:?} escapes its descriptor",
                    call.name
                ));
            }
        }
    }
    let resolved_scope = scope(&resolved, roots)?;
    let confined = matches!(
        (descriptor.scope, resolved_scope),
        (Scope::V1, Scope::V1) | (Scope::Target, Scope::Target) | (Scope::StateParent, Scope::V1)
    );
    if !confined {
        return Err(format!(
            "{} resolves {relative:?} from {} across authority scopes",
            call.name,
            descriptor.resolved.display()
        ));
    }
    Ok(MutationUse {
        scope: resolved_scope,
        resolved,
    })
}

fn direct_path_mutation(call: &TraceCall) -> Result<Option<Vec<MutationUse>>, String> {
    Err(format!(
        "{} is a path-based mutation without a directory descriptor",
        call.raw
    ))
}

fn content_descriptor_use(
    call: &TraceCall,
    fd_index: usize,
    roots: &Roots,
) -> Result<Option<Vec<MutationUse>>, String> {
    let argument = call_argument(call, fd_index)?;
    if fd_path(argument).is_none() {
        return Ok(None);
    }
    Ok(Some(vec![descriptor_use(call, fd_index, roots)?]))
}

fn open_is_mutating(call: &TraceCall, flags_index: usize) -> Result<bool, String> {
    let flags = call_argument(call, flags_index)?;
    Ok(["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_TMPFILE"]
        .iter()
        .any(|flag| flags.contains(flag)))
}

fn mutation_uses(call: &TraceCall, roots: &Roots) -> Result<Option<Vec<MutationUse>>, String> {
    let uses = match call.name.as_str() {
        // `assert_path_authority_discipline` separately confines observation
        // calls that carry paths; they do not mutate the filesystem.
        "stat" | "lstat" | "fstat" | "newfstatat" | "statx" | "statfs" | "fstatfs" | "access"
        | "faccessat" | "faccessat2" | "readlink" | "readlinkat" | "chdir" | "fchdir"
        | "getxattr" | "lgetxattr" | "fgetxattr" | "listxattr" | "llistxattr" | "flistxattr" => {
            return Ok(None);
        }
        "write" | "writev" | "pwrite64" | "pwritev" | "pwritev2" => {
            return content_descriptor_use(call, 0, roots);
        }
        "copy_file_range" | "splice" => return content_descriptor_use(call, 2, roots),
        "sendfile" => return content_descriptor_use(call, 0, roots),
        "open" if open_is_mutating(call, 1)? => return direct_path_mutation(call),
        "openat" | "openat2" if open_is_mutating(call, 2)? => {
            vec![relative_use(call, 0, 1, roots)?]
        }
        "open" | "openat" | "openat2" => return Ok(None),
        "creat" | "mkdir" | "link" | "rename" | "unlink" | "rmdir" | "symlink" | "mknod"
        | "chmod" | "chown" | "lchown" | "truncate" | "utime" | "utimes" | "setxattr"
        | "lsetxattr" | "removexattr" | "lremovexattr" => {
            return direct_path_mutation(call);
        }
        "mkdirat" | "mknodat" | "fchmodat" | "fchmodat2" | "fchownat" | "futimesat"
        | "utimensat" => vec![relative_use(call, 0, 1, roots)?],
        "symlinkat" => vec![relative_use(call, 1, 2, roots)?],
        "linkat" | "renameat" | "renameat2" => vec![
            relative_use(call, 0, 1, roots)?,
            relative_use(call, 2, 3, roots)?,
        ],
        "unlinkat" => vec![relative_use(call, 0, 1, roots)?],
        "fchmod" | "fchown" | "ftruncate" | "fallocate" | "fsetxattr" | "fremovexattr"
        | "flock" | "fsync" | "fdatasync" | "syncfs" => {
            vec![descriptor_use(call, 0, roots)?]
        }
        other => {
            return Err(format!(
                "unclassified focused syscall {other}: {}",
                call.raw
            ));
        }
    };
    Ok(Some(uses))
}

fn trace_failure(trace: &Trace, message: impl std::fmt::Display) -> ! {
    panic!(
        "{} syscall trace assertion failed: {message}\ntrace file: {}\nfocused trace:\n{}",
        trace.label,
        trace.path.display(),
        trace.raw
    )
}

fn transaction_lock_call(call: &TraceCall, roots: &Roots) -> bool {
    call.name == "flock"
        && call.succeeded()
        && call
            .args
            .first()
            .and_then(|argument| fd_path(argument))
            .is_some_and(|path| path == roots.state.join("transaction.lock"))
        && call
            .args
            .get(1)
            .is_some_and(|flags| flags.contains("LOCK_EX") && flags.contains("LOCK_NB"))
}

fn open_path_argument(call: &TraceCall) -> Option<&str> {
    let index = match call.name.as_str() {
        "open" | "creat" => 0,
        "openat" | "openat2" => 1,
        _ => return None,
    };
    call.args
        .get(index)
        .and_then(|argument| path_argument(argument))
}

fn opened_descriptor_path(call: &TraceCall) -> Option<PathBuf> {
    (call.succeeded() && open_path_argument(call).is_some())
        .then(|| fd_path(&call.result))
        .flatten()
}

fn authority_root_open(call: &TraceCall) -> bool {
    if !call.succeeded()
        || open_path_argument(call) != Some("/")
        || opened_descriptor_path(call).as_deref() != Some(Path::new("/"))
    {
        return false;
    }
    let flags = match call.name.as_str() {
        "open" => call.args.get(1),
        "openat" | "openat2" => call.args.get(2),
        _ => None,
    };
    flags.is_some_and(|flags| {
        ["O_PATH", "O_DIRECTORY", "O_NOFOLLOW"]
            .iter()
            .all(|required| has_symbolic_flag(flags, required))
    })
}

fn authority_ancestor(path: &Path, roots: &Roots) -> bool {
    roots.state_parent.starts_with(path) || roots.target.starts_with(path)
}

fn hardened_parent_open(call: &TraceCall, parent: &Path, roots: &Roots) -> bool {
    if call.name != "openat"
        || !call.succeeded()
        || call.args.get(1).and_then(|value| path_argument(value)) != Some("..")
    {
        return false;
    }
    let Some(flags) = call.args.get(2) else {
        return false;
    };
    let Some(opened) = opened_descriptor_path(call) else {
        return false;
    };
    let expected = parent.parent().unwrap_or(parent);
    opened == expected
        && authority_ancestor(&opened, roots)
        && ["O_PATH", "O_DIRECTORY", "O_NOFOLLOW"]
            .iter()
            .all(|required| has_symbolic_flag(flags, required))
}

fn append_relative(base: &Path, relative: &Path) -> Result<PathBuf, String> {
    let mut resolved = base.to_path_buf();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => resolved.push(component),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "path {relative:?} is not descriptor-relative and beneath its authority"
                ));
            }
        }
    }
    Ok(resolved)
}

fn validate_path_authority_discipline(calls: &[TraceCall], roots: &Roots) -> Result<(), String> {
    let trust_start = calls
        .iter()
        .position(authority_root_open)
        .ok_or_else(|| "no hardened filesystem-root authority open was observed".to_owned())?;

    for call in &calls[trust_start..] {
        if authority_root_open(call) {
            continue;
        }
        for argument in path_arguments(call)? {
            match argument {
                PathArgument::Direct { path } => {
                    let value = call_argument(call, path)?;
                    let value = path_argument(value).ok_or_else(|| {
                        format!(
                            "{} direct path argument {value:?} is not an untruncated quoted path: {}",
                            call.name, call.raw
                        )
                    })?;
                    return Err(format!(
                        "{} uses direct path {value:?} after trust establishment: {}",
                        call.name, call.raw
                    ));
                }
                PathArgument::DescriptorRelative { descriptor, path } => {
                    let descriptor_value = call_argument(call, descriptor)?;
                    let parent = fd_path(descriptor_value).ok_or_else(|| {
                        format!(
                            "{} path descriptor {descriptor_value:?} lacks a usable -yy annotation: {}",
                            call.name, call.raw
                        )
                    })?;
                    let path_value = call_argument(call, path)?;
                    let relative = path_argument(path_value).ok_or_else(|| {
                        format!(
                            "{} path argument {path_value:?} is not an untruncated quoted path: {}",
                            call.name, call.raw
                        )
                    })?;
                    let relative = Path::new(relative);
                    if relative.is_absolute() {
                        return Err(format!(
                            "{} uses absolute path {} after trust establishment: {}",
                            call.name,
                            relative.display(),
                            call.raw
                        ));
                    }
                    if relative == Path::new("..") && hardened_parent_open(call, &parent, roots) {
                        continue;
                    }
                    let resolved = append_relative(&parent, relative)?;
                    if scope(&parent, roots).is_ok() {
                        if scope(&parent, roots)? == Scope::StateParent
                            && scope(&resolved, roots)? == Scope::StateParent
                        {
                            if mutation_uses(call, roots)?.is_some() {
                                return Err(format!(
                                    "{} mutates the state parent outside a staged v1 root: {}",
                                    call.name, call.raw
                                ));
                            }
                        } else {
                            relative_use(call, descriptor, path, roots)?;
                        }
                    } else {
                        if !authority_ancestor(&parent, roots)
                            || !authority_ancestor(&resolved, roots)
                        {
                            return Err(format!(
                                "{} traverses outside configured authority ancestry from {} to {}: {}",
                                call.name,
                                parent.display(),
                                resolved.display(),
                                call.raw
                            ));
                        }
                        if mutation_uses(call, roots)?.is_some() {
                            return Err(format!(
                                "{} mutates an authority before its descriptor is pinned: {}",
                                call.name, call.raw
                            ));
                        }
                    }
                }
            }
        }
    }

    for (authority, label) in [(&roots.state, "v1"), (&roots.target, "target")] {
        if !calls
            .iter()
            .any(|call| opened_descriptor_path(call).as_deref() == Some(authority))
        {
            return Err(format!(
                "no successful descriptor-relative open pinned the {label} authority {}",
                authority.display()
            ));
        }
    }
    Ok(())
}

fn assert_path_authority_discipline(trace: &Trace, roots: &Roots) {
    if let Err(error) = validate_path_authority_discipline(&trace.calls, roots) {
        trace_failure(trace, error);
    }
}

fn pinned_openat2_scope(call: &TraceCall, roots: &Roots) -> Option<Scope> {
    if call.name != "openat2" || !call.succeeded() {
        return None;
    }
    let parent = call.args.first().and_then(|argument| fd_path(argument))?;
    scope(&parent, roots)
        .ok()
        .filter(|scope| matches!(scope, Scope::V1 | Scope::Target))
}

fn assert_openat2_resolution(trace: &Trace, roots: &Roots) {
    let mut scoped_calls = BTreeMap::from([(Scope::V1, 0_usize), (Scope::Target, 0)]);
    let mut child_calls = BTreeMap::from([(Scope::V1, 0_usize), (Scope::Target, 0)]);
    for call in &trace.calls {
        let Some(call_scope) = pinned_openat2_scope(call, roots) else {
            continue;
        };
        *scoped_calls.get_mut(&call_scope).expect("known scope") += 1;
        let how = call_argument(call, 2)
            .unwrap_or_else(|error| trace_failure(trace, format!("{error}\ncall: {}", call.raw)));
        for required in [
            "RESOLVE_BENEATH",
            "RESOLVE_NO_SYMLINKS",
            "RESOLVE_NO_MAGICLINKS",
        ] {
            if !has_symbolic_flag(how, required) {
                trace_failure(
                    trace,
                    format!(
                        "successful openat2 below a pinned {call_scope:?} authority omitted {required}: {}",
                        call.raw
                    ),
                );
            }
        }
        let path = call_argument(call, 1)
            .ok()
            .and_then(path_argument)
            .unwrap_or_else(|| {
                trace_failure(
                    trace,
                    format!(
                        "successful openat2 below a pinned authority has an unusable path: {}",
                        call.raw
                    ),
                )
            });
        let path = Path::new(path);
        if path.is_absolute() {
            trace_failure(
                trace,
                format!(
                    "successful openat2 below a pinned authority used an absolute path: {}",
                    call.raw
                ),
            );
        }
        let traverses_child = path
            .components()
            .any(|component| !matches!(component, Component::CurDir));
        if traverses_child {
            *child_calls.get_mut(&call_scope).expect("known scope") += 1;
            if !has_symbolic_flag(how, "RESOLVE_NO_XDEV") {
                trace_failure(
                    trace,
                    format!(
                        "successful openat2 child traversal below a pinned {call_scope:?} authority omitted RESOLVE_NO_XDEV: {}",
                        call.raw
                    ),
                );
            }
        }
    }
    for (call_scope, label) in [(Scope::V1, "v1"), (Scope::Target, "target")] {
        if scoped_calls[&call_scope] == 0 {
            trace_failure(
                trace,
                format!("no successful openat2 call used a pinned {label} authority"),
            );
        }
        if child_calls[&call_scope] == 0 {
            trace_failure(
                trace,
                format!(
                    "no successful openat2 child traversal demonstrated RESOLVE_NO_XDEV below the pinned {label} authority"
                ),
            );
        }
    }
}

fn assert_trace_discipline(trace: &Trace, roots: &Roots) {
    assert_no_experimental_sibling_access(trace, roots);
    assert_path_authority_discipline(trace, roots);
    let mut mutation_count = 0;
    let mut target_mutations = Vec::new();
    for (index, call) in trace.calls.iter().enumerate() {
        let uses = mutation_uses(call, roots)
            .unwrap_or_else(|error| trace_failure(trace, format!("{error}\ncall: {}", call.raw)));
        if let Some(uses) = uses {
            mutation_count += 1;
            if uses.iter().any(|usage| usage.scope == Scope::Target) {
                target_mutations.push(index);
            }
        }
    }
    if mutation_count == 0 {
        trace_failure(trace, "no filesystem mutation syscalls were observed");
    }
    if target_mutations.is_empty() {
        trace_failure(trace, "no managed-target mutation syscalls were observed");
    }

    let lock_index = trace
        .calls
        .iter()
        .position(|call| transaction_lock_call(call, roots))
        .unwrap_or_else(|| {
            trace_failure(
                trace,
                "no successful transaction.lock flock(LOCK_EX|LOCK_NB) was observed",
            )
        });
    if let Some(index) = target_mutations
        .iter()
        .copied()
        .find(|index| *index <= lock_index)
    {
        trace_failure(
            trace,
            format!(
                "target mutation at parsed call {index} precedes transaction lock at {lock_index}: {}",
                trace.calls[index].raw
            ),
        );
    }
    assert_openat2_resolution(trace, roots);
}

fn assert_read_only_trace(trace: &Trace, roots: &Roots) {
    assert_no_experimental_sibling_access(trace, roots);
    assert_path_authority_discipline(trace, roots);
    for call in &trace.calls {
        if let Some(uses) = mutation_uses(call, roots)
            .unwrap_or_else(|error| trace_failure(trace, format!("{error}\ncall: {}", call.raw)))
        {
            trace_failure(
                trace,
                format!(
                    "read-only inspection attempted a mutating syscall with {uses:?}: {}",
                    call.raw
                ),
            );
        }
    }
    assert_openat2_resolution(trace, roots);
}

fn assert_no_experimental_sibling_access(trace: &Trace, roots: &Roots) {
    let absolute = roots.experimental.to_string_lossy();
    for call in &trace.calls {
        if call.raw.contains(absolute.as_ref()) || call.raw.contains("\"malm-v1\"") {
            trace_failure(
                trace,
                format!(
                    "successor syscall mentions the inaccessible experimental sibling: {}",
                    call.raw
                ),
            );
        }
    }
}

fn assert_experimental_sibling_unchanged(roots: &Roots) {
    assert_eq!(
        fs::symlink_metadata(&roots.experimental)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0
    );
    fs::set_permissions(&roots.experimental, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fs::read(roots.experimental.join("transactions/sentinel")).unwrap(),
        b"protected experimental state\n"
    );
}

fn successful_link_position(
    trace: &Trace,
    parent: &Path,
    leaf: impl Fn(&str) -> bool,
) -> Option<usize> {
    trace.calls.iter().position(|call| {
        call.name == "linkat"
            && call.succeeded()
            && call
                .args
                .get(2)
                .and_then(|argument| fd_path(argument))
                .is_some_and(|path| path == parent)
            && call
                .args
                .get(3)
                .and_then(|argument| path_argument(argument))
                .is_some_and(&leaf)
    })
}

fn rename_arguments(call: &TraceCall) -> Option<(PathBuf, &str, PathBuf, &str)> {
    if !matches!(call.name.as_str(), "renameat" | "renameat2") || !call.succeeded() {
        return None;
    }
    Some((
        fd_path(call.args.first()?)?,
        path_argument(call.args.get(1)?)?,
        fd_path(call.args.get(2)?)?,
        path_argument(call.args.get(3)?)?,
    ))
}

fn source_identity_check(call: &TraceCall, pid: Option<u32>, parent: &Path, leaf: &str) -> bool {
    if !call.succeeded() || call.pid != pid {
        return false;
    }
    let flags_index = match call.name.as_str() {
        "newfstatat" => 3,
        "statx" => 2,
        _ => return false,
    };
    call.args
        .first()
        .and_then(|argument| fd_path(argument))
        .is_some_and(|actual| actual == parent)
        && call
            .args
            .get(1)
            .and_then(|argument| path_argument(argument))
            == Some(leaf)
        && call
            .args
            .get(flags_index)
            .is_some_and(|flags| has_symbolic_flag(flags, "AT_SYMLINK_NOFOLLOW"))
}

fn target_mutation(call: &TraceCall, roots: &Roots) -> Result<bool, String> {
    Ok(mutation_uses(call, roots)?
        .is_some_and(|uses| uses.iter().any(|usage| usage.scope == Scope::Target)))
}

fn assert_backup_source_identity_checks(trace: &Trace, roots: &Roots) {
    let batch_boundary = trace
        .calls
        .iter()
        .position(|call| transaction_lock_call(call, roots))
        .unwrap_or_else(|| {
            trace_failure(
                trace,
                "no transaction lock was available as the target mutation batch boundary",
            )
        });
    let mut backup_renames = 0;
    for (rename_index, rename) in trace.calls.iter().enumerate() {
        let Some((old_parent, old, new_parent, new)) = rename_arguments(rename) else {
            continue;
        };
        if old_parent != new_parent
            || !(old_parent == roots.target || old_parent.starts_with(&roots.target))
            || old.starts_with(".malm-")
            || !new.starts_with(".malm-")
            || !new.ends_with("-backup")
        {
            continue;
        }
        backup_renames += 1;
        let prior_mutation = (batch_boundary..rename_index)
            .rev()
            .find(|index| {
                target_mutation(&trace.calls[*index], roots).unwrap_or_else(|error| {
                    trace_failure(trace, format!("{error}\ncall: {}", trace.calls[*index].raw))
                })
            })
            .unwrap_or(batch_boundary);
        if !trace.calls[prior_mutation + 1..rename_index]
            .iter()
            .any(|call| source_identity_check(call, rename.pid, &old_parent, old))
        {
            trace_failure(
                trace,
                format!(
                    "target source {}/{} lacked a successful AT_SYMLINK_NOFOLLOW identity check after parsed call {prior_mutation} and before its backup rename at parsed call {rename_index}: {}",
                    old_parent.display(),
                    old,
                    rename.raw
                ),
            );
        }
    }
    if backup_renames == 0 {
        trace_failure(
            trace,
            "no existing target leaf was renamed to a transaction backup",
        );
    }
}

fn successful_fsync_between(
    trace: &Trace,
    path: &Path,
    after: usize,
    before: usize,
) -> Option<usize> {
    trace.calls[after + 1..before]
        .iter()
        .position(|call| {
            call.name == "fsync"
                && call.succeeded()
                && call
                    .args
                    .first()
                    .and_then(|argument| fd_path(argument))
                    .is_some_and(|actual| actual == path)
        })
        .map(|relative| after + 1 + relative)
}

fn successful_fsync_after(trace: &Trace, path: &Path, after: usize) -> Option<usize> {
    successful_fsync_between(trace, path, after, trace.calls.len())
}

fn root_publication_position(trace: &Trace, roots: &Roots) -> Option<usize> {
    trace.calls.iter().position(|call| {
        call.name == "renameat2"
            && call.succeeded()
            && call.args.len() == 5
            && call
                .args
                .first()
                .and_then(|argument| fd_path(argument))
                .is_some_and(|path| path == roots.state_parent)
            && call
                .args
                .get(1)
                .and_then(|argument| path_argument(argument))
                .is_some_and(|leaf| leaf.starts_with(".malm.init-"))
            && call
                .args
                .get(2)
                .and_then(|argument| fd_path(argument))
                .is_some_and(|path| path == roots.state_parent)
            && call
                .args
                .get(3)
                .and_then(|argument| path_argument(argument))
                == Some("malm")
            && call
                .args
                .get(4)
                .is_some_and(|flags| has_symbolic_flag(flags, "RENAME_NOREPLACE"))
    })
}

fn catalog_publication(call: &TraceCall, roots: &Roots) -> bool {
    if !call.succeeded() {
        return false;
    }
    let state = roots.state.join("state");
    match call.name.as_str() {
        "linkat" => {
            call.args
                .get(2)
                .and_then(|argument| fd_path(argument))
                .is_some_and(|path| path == state)
                && call
                    .args
                    .get(3)
                    .and_then(|argument| path_argument(argument))
                    == Some("catalog.json")
        }
        "renameat" | "renameat2" => {
            rename_arguments(call).is_some_and(|(old_parent, old, new_parent, new)| {
                old_parent == state
                    && new_parent == state
                    && (old == "catalog.json"
                        || new == "catalog.json"
                        || old.starts_with(".catalog.json")
                        || new.starts_with(".catalog.json"))
            })
        }
        _ => false,
    }
}

fn transaction_authority_mutation(call: &TraceCall, roots: &Roots) -> bool {
    if !call.succeeded()
        || !matches!(
            call.name.as_str(),
            "linkat" | "renameat" | "renameat2" | "unlinkat"
        )
    {
        return false;
    }
    mutation_uses(call, roots)
        .ok()
        .flatten()
        .is_some_and(|uses| {
            uses.iter()
                .any(|usage| usage.resolved.starts_with(roots.state.join("transactions")))
        })
}

fn assert_target_mutation_fsync_before_journal(
    trace: &Trace,
    roots: &Roots,
    mutation: usize,
    parent: &Path,
    description: &str,
) {
    let journal = trace.calls[mutation + 1..]
        .iter()
        .position(|call| transaction_authority_mutation(call, roots))
        .map(|relative| mutation + 1 + relative)
        .unwrap_or_else(|| {
            trace_failure(
                trace,
                format!("{description} had no dependent transaction-journal publication"),
            )
        });
    if successful_fsync_between(trace, parent, mutation, journal).is_none() {
        trace_failure(
            trace,
            format!(
                "{description} was not followed by a parent fsync before transaction-journal publication"
            ),
        );
    }
}

fn assert_content_and_metadata_families(trace: &Trace, roots: &Roots) {
    for (scope, label) in [(Scope::V1, "state"), (Scope::Target, "target")] {
        require_trace_assertion(
            trace,
            trace.calls.iter().any(|call| {
                matches!(
                    call.name.as_str(),
                    "write"
                        | "writev"
                        | "pwrite64"
                        | "pwritev"
                        | "pwritev2"
                        | "copy_file_range"
                        | "sendfile"
                        | "splice"
                ) && call.succeeded()
                    && mutation_uses(call, roots)
                        .ok()
                        .flatten()
                        .is_some_and(|uses| uses.iter().any(|usage| usage.scope == scope))
            }),
            &format!("no traced content-write syscall mutated {label} storage"),
        );
        require_trace_assertion(
            trace,
            trace.calls.iter().any(|call| {
                matches!(
                    call.name.as_str(),
                    "fchmod"
                        | "fchown"
                        | "ftruncate"
                        | "fallocate"
                        | "fsetxattr"
                        | "fremovexattr"
                        | "fchmodat"
                        | "fchownat"
                        | "utimensat"
                ) && call.succeeded()
                    && mutation_uses(call, roots)
                        .ok()
                        .flatten()
                        .is_some_and(|uses| uses.iter().any(|usage| usage.scope == scope))
            }),
            &format!("no traced metadata-mutation syscall mutated {label} storage"),
        );
    }
}

fn successful_flock(trace: &Trace, path: &Path) -> bool {
    trace.calls.iter().any(|call| {
        call.name == "flock"
            && call.succeeded()
            && call
                .args
                .first()
                .and_then(|argument| fd_path(argument))
                .is_some_and(|actual| actual == path)
            && call
                .args
                .get(1)
                .is_some_and(|flags| flags.contains("LOCK_EX") && flags.contains("LOCK_NB"))
    })
}

fn require_trace_assertion(trace: &Trace, condition: bool, message: &str) {
    if !condition {
        trace_failure(trace, message);
    }
}

fn assert_lifecycle_publications(trace: &Trace, roots: &Roots) {
    let root_publish = root_publication_position(trace, roots).unwrap_or_else(|| {
        trace_failure(
            trace,
            "v1 root was not published by successful renameat2(..., RENAME_NOREPLACE)",
        )
    });
    let descriptor_link =
        successful_link_position(trace, &roots.state, |leaf| leaf == "descriptor.json")
            .unwrap_or_else(|| {
                trace_failure(
                    trace,
                    "descriptor.json was not published by descriptor-relative linkat",
                )
            });
    require_trace_assertion(
        trace,
        root_publish < descriptor_link,
        "descriptor authority was published before the root renameat2 completed",
    );
    let initial_catalog = successful_link_position(trace, &roots.state.join("state"), |leaf| {
        leaf == "catalog.json"
    })
    .unwrap_or_else(|| trace_failure(trace, "initial catalog was not atomically linked"));
    let root_sync = successful_fsync_between(trace, &roots.state, descriptor_link, initial_catalog)
        .unwrap_or_else(|| {
            trace_failure(
                trace,
                "root directory was not fsynced after descriptor link and before catalog authority",
            )
        });
    let parent_sync =
        successful_fsync_after(trace, &roots.state_parent, root_sync).unwrap_or_else(|| {
            trace_failure(
                trace,
                "state parent was not fsynced after no-replace root publication",
            )
        });
    require_trace_assertion(
        trace,
        root_publish < root_sync && root_sync < parent_sync,
        "root publication fsync ordering is invalid",
    );
    require_trace_assertion(
        trace,
        successful_flock(trace, &roots.state.join("maintenance.lock")),
        "prepared publication did not acquire maintenance.lock with LOCK_EX|LOCK_NB",
    );
    let blobs = roots.state.join("objects/blobs");
    let blob_link = successful_link_position(trace, &blobs, |leaf| leaf.starts_with("sha256-"))
        .unwrap_or_else(|| {
            trace_failure(
                trace,
                "artifact blob was not atomically linked into the CAS",
            )
        });
    let prepared = roots.state.join("prepared");
    let prepared_link = successful_link_position(trace, &prepared, |leaf| leaf.starts_with("pp-"))
        .unwrap_or_else(|| trace_failure(trace, "prepared record was not atomically linked"));
    require_trace_assertion(
        trace,
        blob_link < prepared_link,
        "prepared record was published before its artifact blob",
    );
    let blob_sync = successful_fsync_between(trace, &blobs, blob_link, prepared_link)
        .unwrap_or_else(|| {
            trace_failure(
                trace,
                "blob directory was not fsynced after blob link and before prepared authority",
            )
        });
    let prepared_sync =
        successful_fsync_after(trace, &prepared, prepared_link).unwrap_or_else(|| {
            trace_failure(
                trace,
                "prepared directory was not fsynced after prepared-record link",
            )
        });
    require_trace_assertion(
        trace,
        blob_link < blob_sync && blob_sync < prepared_link && prepared_link < prepared_sync,
        "blob/prepared publication fsync ordering is invalid",
    );

    let generations = roots.state.join("state/generations");
    let generation_links = trace
        .calls
        .iter()
        .enumerate()
        .filter(|(_, call)| {
            call.name == "linkat"
                && call.succeeded()
                && call
                    .args
                    .get(2)
                    .and_then(|argument| fd_path(argument))
                    .is_some_and(|path| path == generations)
                && call
                    .args
                    .get(3)
                    .and_then(|argument| path_argument(argument))
                    .is_some_and(|leaf| leaf.starts_with("sha256-"))
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    require_trace_assertion(
        trace,
        !generation_links.is_empty(),
        "no immutable state generation publication was traced",
    );
    for generation_link in generation_links {
        let catalog = trace.calls[generation_link + 1..]
            .iter()
            .position(|call| catalog_publication(call, roots))
            .map(|relative| generation_link + 1 + relative)
            .unwrap_or_else(|| {
                trace_failure(
                    trace,
                    format!(
                        "generation link at parsed call {generation_link} has no dependent catalog publication"
                    ),
                )
            });
        if successful_fsync_between(trace, &generations, generation_link, catalog).is_none() {
            trace_failure(
                trace,
                format!(
                    "generation directory was not fsynced after link at parsed call {generation_link} and before catalog publication at {catalog}"
                ),
            );
        }
    }
    assert_content_and_metadata_families(trace, roots);
}

fn assert_commit_mutations(trace: &Trace, roots: &Roots) {
    let parent = roots.target.join("config");
    for leaf in ["replaced.conf", "removed.conf"] {
        let backup = trace
            .calls
            .iter()
            .enumerate()
            .find_map(|(index, call)| {
                rename_arguments(call).and_then(|(old_parent, old, new_parent, new)| {
                    (old_parent == parent
                        && new_parent == parent
                        && old == leaf
                        && new.starts_with(".malm-")
                        && new.ends_with("-backup"))
                    .then_some(index)
                })
            })
            .unwrap_or_else(|| {
                trace_failure(
                    trace,
                    format!("nonempty {leaf} was not moved to a pinned backup during commit"),
                )
            });
        assert_target_mutation_fsync_before_journal(
            trace,
            roots,
            backup,
            &parent,
            &format!("backup rename for {leaf}"),
        );
    }
    let target_publications = trace
        .calls
        .iter()
        .enumerate()
        .filter_map(|(index, call)| {
            rename_arguments(call).and_then(|(old_parent, staging, new_parent, leaf)| {
                (old_parent == parent
                    && new_parent == parent
                    && staging.starts_with(".malm-")
                    && staging.ends_with("-new")
                    && matches!(leaf, "replaced.conf" | "removed.conf"))
                .then(|| (index, staging.to_owned(), leaf.to_owned()))
            })
        })
        .collect::<Vec<_>>();
    require_trace_assertion(
        trace,
        target_publications.len() >= 3,
        "baseline and replacement target files were not published by staging rename",
    );
    for (publication, staging, leaf) in target_publications {
        let staging_link = trace.calls[..publication]
            .iter()
            .rposition(|call| {
                call.name == "linkat"
                    && call.succeeded()
                    && call
                        .args
                        .get(2)
                        .and_then(|argument| fd_path(argument))
                        .is_some_and(|path| path == parent)
                    && call
                        .args
                        .get(3)
                        .and_then(|argument| path_argument(argument))
                        == Some(staging.as_str())
            })
            .unwrap_or_else(|| {
                trace_failure(
                    trace,
                    format!("target publication for {leaf} had no staging link"),
                )
            });
        if successful_fsync_between(trace, &parent, staging_link, publication).is_none() {
            trace_failure(
                trace,
                format!(
                    "target staging link for {leaf} was not fsynced before final publication rename"
                ),
            );
        }
        assert_target_mutation_fsync_before_journal(
            trace,
            roots,
            publication,
            &parent,
            &format!("target publication rename for {leaf}"),
        );
    }
    assert_backup_source_identity_checks(trace, roots);
}

fn assert_recovery_mutations(trace: &Trace, roots: &Roots) {
    let parent = roots.target.join("config");
    for leaf in ["replaced.conf", "removed.conf"] {
        let restore = trace
            .calls
            .iter()
            .enumerate()
            .find_map(|(index, call)| {
                rename_arguments(call).and_then(|(old_parent, old, new_parent, new)| {
                    (old_parent == parent
                        && new_parent == parent
                        && old.starts_with(".malm-")
                        && old.ends_with("-backup")
                        && new == leaf)
                        .then_some(index)
                })
            })
            .unwrap_or_else(|| {
                trace_failure(
                    trace,
                    format!("recovery did not restore the pinned backup for {leaf}"),
                )
            });
        assert_target_mutation_fsync_before_journal(
            trace,
            roots,
            restore,
            &parent,
            &format!("recovery restore rename for {leaf}"),
        );
    }
}

fn probe_strace() -> Result<(), String> {
    let output = Command::new("strace")
        .args(["-f", "-yy", "-s", "4096", "-e"])
        .arg(format!("trace={TRACE_SYSCALLS}"))
        .args(["--", "/bin/sh", "-c", ": </dev/null"])
        .output()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                "strace was not found in PATH".to_owned()
            } else {
                format!("could not execute strace: {error}")
            }
        })?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "strace is present but does not support the required -f -yy focused trace: status {}\n{stderr}",
            output.status
        ));
    }
    let calls = parse_trace(&stderr)
        .map_err(|error| format!("unsupported strace output: {error}\n{stderr}"))?;
    if !calls
        .iter()
        .any(|call| matches!(call.name.as_str(), "open" | "openat" | "openat2"))
    {
        return Err(format!(
            "unsupported strace output: probe observed no open syscall\n{stderr}"
        ));
    }
    Ok(())
}

fn strace_is_required() -> bool {
    std::env::var("MALM_REQUIRE_STRACE").as_deref() == Ok("1")
}

fn strace_available_or_skip() -> bool {
    match probe_strace() {
        Ok(()) => true,
        Err(reason) if strace_is_required() => {
            panic!("MALM_REQUIRE_STRACE=1 requires usable strace: {reason}")
        }
        Err(reason) => {
            eprintln!(
                "skipping v1 syscall trace integration test: {reason}; set MALM_REQUIRE_STRACE=1 to require it"
            );
            false
        }
    }
}

fn run_traced(root: &Path, mode: &str, trace_path: &Path, label: &'static str) -> Trace {
    let output = Command::new("strace")
        .args(["-f", "-yy", "-s", "4096", "-o"])
        .arg(trace_path)
        .arg("-e")
        .arg(format!("trace={TRACE_SYSCALLS}"))
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "syscall_trace_child", "--nocapture"])
        .env(CHILD_MODE, mode)
        .env(CHILD_ROOT, root)
        .env_remove("MALM_FAILPOINT")
        .env_remove("MALM_FAILPOINT_MODE")
        .env_remove("MALM_FAILPOINT_MARKER")
        .env_remove("MALM_FAILPOINT_CONTINUE")
        .env_remove("MALM_FAILPOINT_TIMEOUT_MS")
        .output()
        .unwrap();
    let raw = fs::read_to_string(trace_path)
        .unwrap_or_else(|error| panic!("read {label} trace {}: {error}", trace_path.display()));
    assert!(
        output.status.success(),
        "{label} trace child failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}\ntrace:\n{raw}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = parse_trace(&raw).unwrap_or_else(|error| {
        panic!(
            "{label} produced unsupported strace output: {error}\ntrace file: {}\n{raw}",
            trace_path.display()
        )
    });
    Trace {
        label,
        path: trace_path.to_path_buf(),
        raw,
        calls,
    }
}

fn run_crashing_commit(root: &Path) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "syscall_trace_child", "--nocapture"])
        .env(CHILD_MODE, "crash")
        .env(CHILD_ROOT, root)
        .env("MALM_FAILPOINT", "v1.commit.after_operation=4")
        .env_remove("MALM_FAILPOINT_MODE")
        .env_remove("MALM_FAILPOINT_MARKER")
        .env_remove("MALM_FAILPOINT_CONTINUE")
        .env_remove("MALM_FAILPOINT_TIMEOUT_MS")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "failpoint commit unexpectedly survived\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn reserved_target_entries(target: &Path) -> Vec<String> {
    let mut entries = fs::read_dir(target.join("config"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(".malm-"))
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

#[test]
fn trace_parser_accepts_current_pid_prefix_forms() {
    let raw = concat!(
        "410 openat2(9</tmp/state/malm>, \"objects\", {flags=O_RDONLY|O_CLOEXEC, resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV}, 24) = 10</tmp/state/malm/objects>\n",
        "[pid 411] renameat2(12</tmp/target/config>, \"old\", 12</tmp/target/config>, \"new\", RENAME_NOREPLACE) = 0\n",
        "flock(13</tmp/state/malm/transaction.lock>, LOCK_EX|LOCK_NB) = 0\n",
        "[pid 412] linkat(14</tmp/state/malm/objects/blobs/#1 (deleted)>, \"\", 15</tmp/state/malm/objects/blobs>, <unfinished ...>\n",
        "[pid 412] <... linkat resumed>\"sha256-example\", AT_EMPTY_PATH) = 0\n",
        "413 newfstatat(12</tmp/target/config>, \"old\",  <unfinished ...>   \n",
        "[pid 413] <... newfstatat resumed>{st_mode=S_IFREG|0600, st_size=8, ...}, AT_SYMLINK_NOFOLLOW) = 0\n",
        "[pid 414] fstat(13</tmp/state/malm/transaction.lock>, {st_mode=S_IFREG|0600, ...}) = 0\n",
        "415 statx(12</tmp/target/config>, \"old\", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS, ...}) = 0\n",
    );
    let calls = parse_trace(raw).unwrap();
    assert_eq!(calls.len(), 7);
    assert_eq!(calls[0].pid, Some(410));
    assert_eq!(calls[0].args.len(), 4);
    assert_eq!(calls[1].pid, Some(411));
    assert_eq!(calls[2].pid, None);
    assert_eq!(calls[3].pid, Some(412));
    assert_eq!(calls[3].args.len(), 5);
    assert_eq!(calls[4].pid, Some(413));
    assert_eq!(calls[4].name, "newfstatat");
    assert_eq!(calls[4].args.len(), 4);
    assert_eq!(calls[5].name, "fstat");
    assert_eq!(calls[6].name, "statx");
    assert!(source_identity_check(
        &calls[4],
        Some(413),
        Path::new("/tmp/target/config"),
        "old"
    ));
    let roots = Roots::at(Path::new("/tmp"));
    for call in &calls[4..] {
        assert!(mutation_uses(call, &roots).unwrap().is_none());
    }
}

#[test]
fn trace_parser_classifies_descriptor_relative_read_and_path_mutation_families() {
    let authority = concat!(
        "open(\"/\", O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW) = 3</>\n",
        "openat2(3</>, \"tmp\", {flags=O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW, resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS}, 24) = 4</tmp>\n",
        "openat2(4</tmp>, \"trace-fixture\", {flags=O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW, resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS}, 24) = 5</tmp/trace-fixture>\n",
        "openat2(5</tmp/trace-fixture>, \"state\", {flags=O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW, resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS}, 24) = 6</tmp/trace-fixture/state>\n",
        "openat2(6</tmp/trace-fixture/state>, \"malm\", {flags=O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW, resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV}, 24) = 7</tmp/trace-fixture/state/malm>\n",
        "openat2(5</tmp/trace-fixture>, \"target\", {flags=O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW, resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS}, 24) = 8</tmp/trace-fixture/target>\n",
    );
    let relative = concat!(
        "newfstatat(7</tmp/trace-fixture/state/malm>, \"descriptor.json\", {st_mode=S_IFREG|0600, ...}, AT_SYMLINK_NOFOLLOW)      = 0\n",
        "statx(8</tmp/trace-fixture/target>, \"config\", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS, ...}) = 0\n",
        "readlinkat(8</tmp/trace-fixture/target>, \"link\", \"destination\", 4096) = 11\n",
        "mkdirat(8</tmp/trace-fixture/target>, \"config\", 0700) = 0\n",
        "linkat(9</tmp/trace-fixture/state/malm/#1 (deleted)>, \"\", 7</tmp/trace-fixture/state/malm>, \"descriptor.copy\", AT_EMPTY_PATH) = 0\n",
        "renameat2(8</tmp/trace-fixture/target>, \"old\", 8</tmp/trace-fixture/target>, \"new\", RENAME_NOREPLACE) = 0\n",
        "unlinkat(8</tmp/trace-fixture/target>, \"old\", 0) = 0\n",
        "fchmodat2(8</tmp/trace-fixture/target>, \"new\", 0600, AT_SYMLINK_NOFOLLOW) = 0\n",
        "fchownat(8</tmp/trace-fixture/target>, \"new\", 1000, 1000, AT_SYMLINK_NOFOLLOW) = 0\n",
        "fsetxattr(10</tmp/trace-fixture/target/new>, \"user.test\", \"x\", 1, 0) = 0\n",
    );
    let calls = parse_trace(&format!("{authority}{relative}")).unwrap();
    let roots = Roots::at(Path::new("/tmp/trace-fixture"));
    validate_path_authority_discipline(&calls, &roots).unwrap();

    assert_eq!(
        path_arguments(&calls[6]).unwrap(),
        [PathArgument::DescriptorRelative {
            descriptor: 0,
            path: 1,
        }]
    );
    assert_eq!(path_arguments(calls.last().unwrap()).unwrap(), []);

    let direct = parse_trace(&format!(
        "{authority}readlink(\"/tmp/trace-fixture/target/link\", \"destination\", 4096) = 11\n"
    ))
    .unwrap();
    let error = validate_path_authority_discipline(&direct, &roots).unwrap_err();
    assert!(error.contains("uses direct path"), "{error}");
}

#[test]
fn v1_filesystem_syscalls_are_descriptor_relative_and_ordered() {
    if !strace_available_or_skip() {
        return;
    }

    let lifecycle = create_fixture();
    let lifecycle_roots = Roots::at(lifecycle.path());
    let lifecycle_trace = run_traced(
        lifecycle.path(),
        "lifecycle",
        &lifecycle.path().join("lifecycle.strace"),
        "initialize/prepare/commit",
    );
    assert_trace_discipline(&lifecycle_trace, &lifecycle_roots);
    assert_lifecycle_publications(&lifecycle_trace, &lifecycle_roots);
    assert_commit_mutations(&lifecycle_trace, &lifecycle_roots);
    assert_eq!(
        fs::read(lifecycle_roots.target.join(REPLACED_PATH)).unwrap(),
        PREPARED_REPLACEMENT
    );
    assert!(!lifecycle_roots.target.join(REMOVED_PATH).exists());
    assert!(reserved_target_entries(&lifecycle_roots.target).is_empty());
    assert_experimental_sibling_unchanged(&lifecycle_roots);

    let recovery = create_fixture();
    let recovery_roots = Roots::at(recovery.path());
    run_crashing_commit(recovery.path());
    assert!(
        recovery_roots
            .state
            .join("transactions/current.json")
            .is_file()
    );
    assert_eq!(
        fs::read(recovery_roots.target.join(REPLACED_PATH)).unwrap(),
        PREPARED_REPLACEMENT
    );
    assert!(!recovery_roots.target.join(REMOVED_PATH).exists());
    let backups = reserved_target_entries(&recovery_roots.target)
        .into_iter()
        .filter(|entry| entry.ends_with("-backup"))
        .collect::<Vec<_>>();
    assert_eq!(backups.len(), 2, "crash fixture backups: {backups:#?}");
    let previous_catalog = fs::read(recovery_roots.state.join("state/catalog.json")).unwrap();

    let recovery_trace = run_traced(
        recovery.path(),
        "recover",
        &recovery.path().join("recovery.strace"),
        "recovery",
    );
    assert_trace_discipline(&recovery_trace, &recovery_roots);
    assert_recovery_mutations(&recovery_trace, &recovery_roots);
    assert_eq!(
        fs::read(recovery_roots.target.join(REPLACED_PATH)).unwrap(),
        ORIGINAL_REPLACED
    );
    assert_eq!(
        fs::read(recovery_roots.target.join(REMOVED_PATH)).unwrap(),
        ORIGINAL_REMOVED
    );
    assert!(reserved_target_entries(&recovery_roots.target).is_empty());
    assert_eq!(
        fs::read(recovery_roots.state.join("state/catalog.json")).unwrap(),
        previous_catalog
    );
    assert_experimental_sibling_unchanged(&recovery_roots);

    let inspection = create_fixture();
    let inspection_roots = Roots::at(inspection.path());
    let engine = make_engine(inspection.path());
    engine.initialize_store().unwrap();
    seed_owned_targets(&engine);
    for lock in ["transaction.lock", "maintenance.lock"] {
        let path = inspection_roots.state.join(lock);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
    drop(engine);
    let inspection_trace = run_traced(
        inspection.path(),
        "inspection",
        &inspection.path().join("inspection.strace"),
        "read-only inspection",
    );
    assert_read_only_trace(&inspection_trace, &inspection_roots);
    assert!(!inspection_roots.state.join("transaction.lock").exists());
    assert!(!inspection_roots.state.join("maintenance.lock").exists());
    assert_experimental_sibling_unchanged(&inspection_roots);
}
