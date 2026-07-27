use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, StatxFlags, fstat, statx};

use super::{EngineError, errno_error};

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
const MAX_MOUNTINFO_BYTES: u64 = 4 * 1024 * 1024;

pub(super) fn directory_is_mount_alias_of(
    protected: &File,
    protected_path: &Path,
    candidate: &File,
    candidate_path: &Path,
) -> Result<bool, EngineError> {
    let protected_stat = fstat(protected)
        .map_err(|source| errno_error("inspect protected root", protected_path, source))?;
    let candidate_stat = fstat(candidate)
        .map_err(|source| errno_error("inspect candidate mount", candidate_path, source))?;
    if protected_stat.st_dev != candidate_stat.st_dev {
        return Ok(false);
    }

    let protected_mount = mount_id(protected, protected_path)?;
    let candidate_mount = mount_id(candidate, candidate_path)?;
    if protected_mount == candidate_mount {
        return Ok(false);
    }

    let evidence = load_mountinfo()?;
    mount_alias_from_evidence(
        protected_mount,
        protected_path,
        candidate_mount,
        candidate_path,
        &evidence,
    )
}

fn mount_id(file: &File, path: &Path) -> Result<u64, EngineError> {
    let stat = statx(
        file,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::MNT_ID,
    )
    .map_err(|source| errno_error("inspect filesystem mount identity", path, source))?;
    if !StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID) {
        return Err(evidence_error(
            path,
            "kernel did not report a mount identity for protected-root proof",
        ));
    }
    Ok(stat.stx_mnt_id)
}

fn load_mountinfo() -> Result<Vec<u8>, EngineError> {
    let path = Path::new(MOUNTINFO_PATH);
    let mut file = File::open(path).map_err(|source| EngineError::Io {
        operation: "open process mount table",
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_MOUNTINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| EngineError::Io {
            operation: "read process mount table",
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MOUNTINFO_BYTES {
        return Err(evidence_error(
            path,
            "process mount table exceeds its size limit",
        ));
    }
    Ok(bytes)
}

#[derive(Debug)]
struct MountRecord {
    device: Vec<u8>,
    root: PathBuf,
    mount_point: PathBuf,
}

impl MountRecord {
    fn filesystem_path(&self, visible: &Path) -> Result<PathBuf, EngineError> {
        let relative = visible.strip_prefix(&self.mount_point).map_err(|_| {
            evidence_error(
                visible,
                "mount identity does not contain the validated path",
            )
        })?;
        Ok(normalize_mount_path(self.root.join(relative)))
    }
}

fn mount_alias_from_evidence(
    protected_mount: u64,
    protected_path: &Path,
    candidate_mount: u64,
    candidate_path: &Path,
    evidence: &[u8],
) -> Result<bool, EngineError> {
    if protected_mount == candidate_mount {
        return Ok(false);
    }
    let protected_record = load_mount_record(evidence, protected_mount)?;
    let candidate_record = load_mount_record(evidence, candidate_mount)?;
    if protected_record.device != candidate_record.device {
        return Ok(false);
    }
    let protected_internal = protected_record.filesystem_path(protected_path)?;
    let candidate_internal = candidate_record.filesystem_path(candidate_path)?;
    Ok(candidate_internal == protected_internal
        || candidate_internal.starts_with(protected_internal))
}

fn load_mount_record(evidence: &[u8], mount_id: u64) -> Result<MountRecord, EngineError> {
    let mut found = None;
    for line in evidence.split(|byte| *byte == b'\n') {
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let Some(id) = fields
            .first()
            .and_then(|field| std::str::from_utf8(field).ok())
            .and_then(|field| field.parse::<u64>().ok())
        else {
            continue;
        };
        if id != mount_id {
            continue;
        }
        let separator = fields.iter().position(|field| *field == b"-");
        if fields.len() < 10
            || separator.is_none_or(|index| index < 6 || index.saturating_add(3) >= fields.len())
        {
            return Err(evidence_error(
                Path::new(MOUNTINFO_PATH),
                format!("mount identity {mount_id} has a malformed process mount record"),
            ));
        }
        let record = MountRecord {
            device: fields[2].to_vec(),
            root: decode_mount_path(fields[3])?,
            mount_point: decode_mount_path(fields[4])?,
        };
        if found.replace(record).is_some() {
            return Err(evidence_error(
                Path::new(MOUNTINFO_PATH),
                format!(
                    "mount identity {mount_id} appears more than once in the process mount table"
                ),
            ));
        }
    }
    found.ok_or_else(|| {
        evidence_error(
            Path::new(MOUNTINFO_PATH),
            format!("mount identity {mount_id} is absent from the process mount table"),
        )
    })
}

fn decode_mount_path(field: &[u8]) -> Result<PathBuf, EngineError> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] != b'\\' {
            decoded.push(field[index]);
            index += 1;
            continue;
        }
        if index + 3 >= field.len()
            || !field[index + 1..=index + 3]
                .iter()
                .all(|byte| (b'0'..=b'7').contains(byte))
        {
            return Err(evidence_error(
                Path::new(MOUNTINFO_PATH),
                "process mount table contains an invalid path escape",
            ));
        }
        let value = u16::from(field[index + 1] - b'0') * 64
            + u16::from(field[index + 2] - b'0') * 8
            + u16::from(field[index + 3] - b'0');
        decoded.push(u8::try_from(value).map_err(|_| {
            evidence_error(
                Path::new(MOUNTINFO_PATH),
                "process mount table contains an out-of-range path escape",
            )
        })?);
        index += 4;
    }
    let path = PathBuf::from(OsString::from_vec(decoded));
    if !path.is_absolute() {
        return Err(evidence_error(
            Path::new(MOUNTINFO_PATH),
            "process mount table contains a relative path",
        ));
    }
    Ok(path)
}

fn normalize_mount_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => {}
        }
    }
    normalized
}

fn evidence_error(path: &Path, detail: impl Into<String>) -> EngineError {
    EngineError::Io {
        operation: "prove protected-root mount identity",
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, detail.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVIDENCE: &[u8] = br#"42 1 8:1 /backing/malm /state/malm rw - ext4 /dev/root rw
43 1 8:1 /backing/malm/private /aliases/final rw - ext4 /dev/root rw
44 1 8:1 /backing/other /state/other rw - ext4 /dev/root rw
45 1 8:1 /backing/other/private /aliases/other rw - ext4 /dev/root rw
46 1 8:1 /backing /aliases/ancestor rw - ext4 /dev/root rw
47 1 8:1 /unrelated /aliases/unrelated rw - ext4 /dev/root rw
48 1 0:9 /backing/malm/private /aliases/other-device rw - tmpfs tmpfs rw
"#;

    #[test]
    fn parsed_mount_evidence_detects_descendant_aliases() {
        assert!(
            mount_alias_from_evidence(
                42,
                Path::new("/state/malm"),
                43,
                Path::new("/aliases/final"),
                EVIDENCE,
            )
            .unwrap()
        );
        assert!(
            mount_alias_from_evidence(
                44,
                Path::new("/state/other"),
                45,
                Path::new("/aliases/other"),
                EVIDENCE,
            )
            .unwrap()
        );
    }

    #[test]
    fn parsed_mount_evidence_supports_symmetric_overlap_without_false_aliases() {
        assert!(
            !mount_alias_from_evidence(
                42,
                Path::new("/state/malm"),
                46,
                Path::new("/aliases/ancestor"),
                EVIDENCE,
            )
            .unwrap()
        );
        assert!(
            mount_alias_from_evidence(
                46,
                Path::new("/aliases/ancestor"),
                42,
                Path::new("/state/malm"),
                EVIDENCE,
            )
            .unwrap()
        );
        assert!(
            !mount_alias_from_evidence(
                42,
                Path::new("/state/malm"),
                47,
                Path::new("/aliases/unrelated"),
                EVIDENCE,
            )
            .unwrap()
        );
        assert!(
            !mount_alias_from_evidence(
                42,
                Path::new("/state/malm"),
                48,
                Path::new("/aliases/other-device"),
                EVIDENCE,
            )
            .unwrap()
        );
    }

    #[test]
    fn incomplete_or_malformed_mount_evidence_fails_closed() {
        assert!(
            mount_alias_from_evidence(
                42,
                Path::new("/state/malm"),
                99,
                Path::new("/aliases/missing"),
                EVIDENCE,
            )
            .is_err()
        );

        let malformed = br#"42 1 8:1 /backing/malm /state/malm rw - ext4 /dev/root rw
43 1 8:1 /backing/malm/invalid\09x /aliases/final rw - ext4 /dev/root rw
"#;
        assert!(
            mount_alias_from_evidence(
                42,
                Path::new("/state/malm"),
                43,
                Path::new("/aliases/final"),
                malformed,
            )
            .is_err()
        );
    }
}
