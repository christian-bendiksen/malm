//! Crash injection around the batched canonical-object barrier.
//!
//! Publication stages many objects into anonymous inodes, pays one `fsync`
//! barrier for the batch, and only then links them under their digests. These
//! tests crash at each point in that sequence and assert the invariant the
//! ordering exists to protect: **a canonical object that has a name has durable
//! content**. Every named object must therefore still load and digest-check
//! after an abrupt abort.

#![cfg(feature = "failpoints")]

use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use malm_archive::USTAR_BLOCK_BYTES;
use malm_engine::{
    ArchiveDeclarationV1, ArchiveLimitsV1, Engine, EngineConfig, EnginePorts, StoreAccess,
};
use malm_types::Digest;

const CRASH_ROOT_ENV: &str = "MALM_CANONICAL_BATCH_CRASH_ROOT";
const CHILD_TEST: &str = "publish_batched_archive_child";

/// Enough entries to cross the staging chunk boundary, so the crash lands
/// mid-batch rather than in a single short chunk.
const ENTRIES: usize = 700;

fn write_octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
}

fn write_text(field: &mut [u8], value: &[u8]) {
    field[..value.len()].copy_from_slice(value);
}

fn set_checksum(header: &mut [u8; USTAR_BLOCK_BYTES]) {
    header[148..156].fill(b' ');
    let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let text = format!("{sum:06o}");
    header[148..154].copy_from_slice(text.as_bytes());
    header[154] = 0;
    header[155] = b' ';
}

fn regular(path: &str, data: &[u8], seed: u64) -> Vec<u8> {
    let mut header = [0_u8; USTAR_BLOCK_BYTES];
    write_text(&mut header[..100], path.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], seed);
    write_octal(&mut header[116..124], seed + 1);
    write_octal(&mut header[124..136], data.len() as u64);
    write_octal(&mut header[136..148], 1_700_000_000 + seed);
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_text(&mut header[265..297], b"user");
    write_text(&mut header[297..329], b"group");
    write_octal(&mut header[329..337], 0);
    write_octal(&mut header[337..345], 0);
    set_checksum(&mut header);

    let mut block = header.to_vec();
    block.extend_from_slice(data);
    let remainder = data.len() % USTAR_BLOCK_BYTES;
    if remainder != 0 {
        block.resize(block.len() + USTAR_BLOCK_BYTES - remainder, 0);
    }
    block
}

/// A tar whose entries all have distinct contents, so each one becomes its own
/// canonical object rather than deduplicating away.
fn payload() -> Vec<u8> {
    let mut bytes = Vec::new();
    for index in 0..ENTRIES {
        let data = format!("canonical batch object {index}\n");
        bytes.extend_from_slice(&regular(
            &format!("payload/file-{index:04}"),
            data.as_bytes(),
            index as u64,
        ));
    }
    bytes.resize(bytes.len() + 2 * USTAR_BLOCK_BYTES, 0);
    bytes
}

fn make_engine(root: &Path) -> Engine {
    let state_home = root.join("state");
    if !state_home.exists() {
        fs::create_dir(&state_home).unwrap();
        fs::set_permissions(&state_home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    Engine::new(
        EngineConfig::from_state_home(&state_home, StoreAccess::ReadWrite).unwrap(),
        EnginePorts::system(),
    )
}

#[test]
fn publish_batched_archive_child() {
    let Some(root) = std::env::var_os(CRASH_ROOT_ENV) else {
        return;
    };
    let bytes = payload();
    let declaration = ArchiveDeclarationV1::posix_ustar(bytes.len() as u64, Digest::sha256(&bytes));
    make_engine(&PathBuf::from(root))
        .decode_and_publish_archive_v1(Cursor::new(bytes), declaration, ArchiveLimitsV1::default())
        .unwrap();
    panic!("configured publication failpoint did not fire");
}

fn crash_at(root: &Path, failpoint: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CRASH_ROOT_ENV, root)
        .env("MALM_FAILPOINT", failpoint)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The abort message names the failpoint alone; a `=nth` suffix selects
    // which hit aborts and is not echoed back.
    let point = failpoint.split_once('=').map_or(failpoint, |(name, _)| name);
    assert!(
        !output.status.success() && stderr.contains(&format!("failpoint {point}: aborting")),
        "child did not abort at {failpoint}\nstatus: {:?}\nstdout:\n{}\nstderr:\n{stderr}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
    );
}

/// Loads every object that has a name and lets the engine digest-check it.
/// Returns how many were found, so a test can also assert it inspected
/// something rather than passing vacuously.
fn assert_every_named_object_verifies(root: &Path, engine: &Engine) -> usize {
    let objects = root.join("state/malm/objects");
    let mut checked = 0;
    for (directory, load) in [
        (
            "files",
            &(|engine: &Engine, digest: &Digest| {
                engine.load_file_object_v1(digest).map(|_| ())
            }) as &dyn Fn(&Engine, &Digest) -> Result<(), malm_engine::EngineError>,
        ),
        ("symlinks", &|engine, digest| {
            engine.load_symlink_object_v1(digest).map(|_| ())
        }),
        ("trees", &|engine, digest| {
            engine.load_tree_object_v1(digest).map(|_| ())
        }),
    ] {
        let path = objects.join(directory);
        if !path.exists() {
            continue;
        }
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let digest = Digest::new(&name)
                .unwrap_or_else(|_| panic!("object name {name} in {directory} is not a digest"));
            load(engine, &digest).unwrap_or_else(|error| {
                panic!("named object {directory}/{name} did not verify after a crash: {error}")
            });
            checked += 1;
        }
    }
    checked
}

#[test]
fn crash_before_the_barrier_leaves_no_named_objects() {
    let temp = tempfile::tempdir().unwrap();
    make_engine(temp.path()).initialize_store().unwrap();

    crash_at(temp.path(), "v1.publish.chunk.before_barrier");

    // Nothing in the batch is named yet, so the store gained no objects at all.
    let engine = make_engine(temp.path());
    assert_eq!(assert_every_named_object_verifies(temp.path(), &engine), 0);
}

#[test]
fn crash_after_the_barrier_leaves_durable_unnamed_objects_only() {
    let temp = tempfile::tempdir().unwrap();
    make_engine(temp.path()).initialize_store().unwrap();

    crash_at(temp.path(), "v1.publish.chunk.after_barrier");

    // The batch is durable but still anonymous, so it simply vanishes.
    let engine = make_engine(temp.path());
    assert_eq!(assert_every_named_object_verifies(temp.path(), &engine), 0);
}

#[test]
fn crash_during_the_link_sweep_leaves_every_named_object_durable() {
    let temp = tempfile::tempdir().unwrap();
    make_engine(temp.path()).initialize_store().unwrap();

    // Abort part-way through linking the first chunk, so some objects are named
    // and the rest are not.
    crash_at(temp.path(), "v1.publish.chunk.during_links=64");

    let engine = make_engine(temp.path());
    let checked = assert_every_named_object_verifies(temp.path(), &engine);
    assert_eq!(
        checked, 64,
        "expected exactly the objects linked before the abort"
    );
}

#[test]
fn republication_after_a_crash_completes_the_archive() {
    let temp = tempfile::tempdir().unwrap();
    make_engine(temp.path()).initialize_store().unwrap();

    crash_at(temp.path(), "v1.publish.chunk.during_links=64");

    let bytes = payload();
    let declaration = ArchiveDeclarationV1::posix_ustar(bytes.len() as u64, Digest::sha256(&bytes));
    let engine = make_engine(temp.path());
    let decoded = engine
        .decode_and_publish_archive_v1(Cursor::new(bytes), declaration, ArchiveLimitsV1::default())
        .unwrap();

    engine.load_tree_object_v1(decoded.root_digest()).unwrap();
    let checked = assert_every_named_object_verifies(temp.path(), &engine);
    assert!(
        checked > ENTRIES,
        "expected every payload object plus its trees, found {checked}"
    );
}
