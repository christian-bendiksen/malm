#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Eq, PartialEq)]
struct EntrySnapshot {
    bytes: Option<Vec<u8>>,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    accessed: (i64, i64),
    modified: (i64, i64),
    changed: (i64, i64),
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, EntrySnapshot> {
    let mut paths = vec![root.to_path_buf()];
    let mut index = 0;
    while index < paths.len() {
        let path = paths[index].clone();
        index += 1;
        if std::fs::symlink_metadata(&path).unwrap().is_dir() {
            let mut children = std::fs::read_dir(&path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            children.sort();
            paths.extend(children);
        }
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            let bytes = metadata.is_file().then(|| std::fs::read(&path).unwrap());
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            (
                relative,
                EntrySnapshot {
                    bytes,
                    mode: metadata.mode(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    links: metadata.nlink(),
                    size: metadata.size(),
                    accessed: (metadata.atime(), metadata.atime_nsec()),
                    modified: (metadata.mtime(), metadata.mtime_nsec()),
                    changed: (metadata.ctime(), metadata.ctime_nsec()),
                },
            )
        })
        .collect()
}

#[test]
fn last_legacy_executable_rejects_the_final_root_unchanged() {
    let Some(legacy_malm) = std::env::var_os("LEGACY_MALM") else {
        assert_ne!(
            std::env::var_os("MALM_REQUIRE_LEGACY_EXECUTABLE").as_deref(),
            Some(std::ffi::OsStr::new("1")),
            "LEGACY_MALM must name the designated predecessor executable"
        );
        eprintln!("LEGACY_MALM is unset; external old-executable rejection leg skipped");
        return;
    };

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let state_home = temp.path().join("state");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&state_home).unwrap();
    std::fs::set_permissions(
        &state_home,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();

    let initialized = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["store", "init"])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state_home)
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "final store initialization failed: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let root = state_home.join("malm");
    let before = snapshot(&root);

    let rejected = Command::new(legacy_malm)
        .args(["state", "fsck"])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state_home)
        .env_remove("MALM_FAILPOINT")
        .output()
        .expect("run LEGACY_MALM executable");
    assert!(
        !rejected.status.success(),
        "legacy executable accepted the final root\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert_eq!(snapshot(&root), before);
}

#[test]
fn successor_rejects_a_root_created_by_the_last_legacy_executable_unchanged() {
    let Some(legacy_malm) = std::env::var_os("LEGACY_MALM") else {
        assert_ne!(
            std::env::var_os("MALM_REQUIRE_LEGACY_EXECUTABLE").as_deref(),
            Some(std::ffi::OsStr::new("1")),
            "LEGACY_MALM must name the designated predecessor executable"
        );
        eprintln!("LEGACY_MALM is unset; external predecessor-root creation leg skipped");
        return;
    };

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let state_home = temp.path().join("state");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&state_home).unwrap();
    std::fs::set_permissions(
        &state_home,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();

    // The designated predecessor creates format.json during its mutating
    // preflight, then fails because the synthetic pin target is absent.
    let created = Command::new(legacy_malm)
        .args(["state", "pin", "phase15-missing-transaction"])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state_home)
        .env_remove("MALM_FAILPOINT")
        .output()
        .expect("run LEGACY_MALM mutating command");
    assert!(
        !created.status.success(),
        "legacy state pin unexpectedly found its synthetic transaction"
    );
    let root = state_home.join("malm");
    let marker = root.join("format.json");
    let marker_bytes = std::fs::read(&marker).unwrap_or_else(|error| {
        panic!(
            "designated predecessor did not create its format.json during mutating preflight: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&created.stdout),
            String::from_utf8_lossy(&created.stderr)
        )
    });
    let marker_value: serde_json::Value = serde_json::from_slice(&marker_bytes).unwrap();
    assert_eq!(marker_value, serde_json::json!({ "version": 2 }));
    let before = snapshot(&root);

    let rejected = Command::new(env!("CARGO_BIN_EXE_malm"))
        .args(["store", "init"])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state_home)
        .env_remove("MALM_FAILPOINT")
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "successor accepted the designated predecessor root\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert_eq!(snapshot(&root), before);
}
