use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use malm_types::Digest;

pub(crate) const MAX_FILE_OBJECT_BYTES: u64 = 17 + 2 + 8 + MAX_FILE_BYTES;
pub(crate) const MAX_SYMLINK_OBJECT_BYTES: u64 = 20 + 2 + 8 + MAX_SYMLINK_BYTES as u64;
pub(crate) const MAX_TREE_OBJECT_BYTES: u64 =
    17 + 2 + 4 + 8 + MAX_ENTRIES as u64 * (8 + 255 + 1 + 4 + 8 + 71 + 8);

const FILE_DOMAIN: &[u8] = b"malm-file-object\0";
const SYMLINK_DOMAIN: &[u8] = b"malm-symlink-object\0";
const TREE_DOMAIN: &[u8] = b"malm-tree-object\0";
const VERSION: u16 = 1;
pub(crate) const MAX_ENTRIES: usize = 100_000;
pub(crate) const MAX_DEPTH: usize = 64;
pub(crate) const MAX_PATH_BYTES: usize = 4096;
pub(crate) const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SYMLINK_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub(crate) struct CanonicalObjects {
    pub(crate) files: BTreeMap<Digest, Arc<[u8]>>,
    pub(crate) symlinks: BTreeMap<Digest, String>,
    pub(crate) trees: BTreeMap<Digest, TreeObject>,
}

impl CanonicalObjects {
    pub(crate) fn empty() -> Self {
        Self {
            files: BTreeMap::new(),
            symlinks: BTreeMap::new(),
            trees: BTreeMap::new(),
        }
    }

    pub(crate) fn validate_tree(&self, root: &Digest) -> Result<(), CanonicalObjectIssue> {
        validate_graph(root, self)
    }

    pub(crate) fn safe_symlink_target(
        &self,
        digest: &Digest,
    ) -> Result<&str, CanonicalObjectIssue> {
        let target = self
            .symlinks
            .get(digest)
            .ok_or_else(|| CanonicalObjectIssue::Missing {
                kind: "symlink",
                digest: digest.clone(),
            })?;
        safe_target_path("link", target)?;
        Ok(target)
    }

    pub(crate) fn tree_file_bytes(&self, root: &Digest) -> Result<u64, CanonicalObjectIssue> {
        fn walk(
            objects: &CanonicalObjects,
            digest: &Digest,
            total: &mut u64,
        ) -> Result<(), CanonicalObjectIssue> {
            let tree = objects
                .trees
                .get(digest)
                .ok_or_else(|| CanonicalObjectIssue::Missing {
                    kind: "tree",
                    digest: digest.clone(),
                })?;
            for entry in &tree.entries {
                match &entry.kind {
                    TreeEntryKind::File { byte_len, .. } => {
                        *total = total
                            .checked_add(*byte_len)
                            .ok_or_else(|| invalid("canonical tree file-byte count overflows"))?;
                    }
                    TreeEntryKind::Directory { digest } => walk(objects, digest, total)?,
                    TreeEntryKind::Symlink { .. } => {}
                }
            }
            Ok(())
        }

        let mut total = 0;
        walk(self, root, &mut total)?;
        Ok(total)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TreeObject {
    pub(crate) root_mode: u32,
    pub(crate) entries: Vec<TreeEntry>,
}

#[derive(Clone, Debug)]
pub(crate) struct TreeEntry {
    pub(crate) name: String,
    pub(crate) mode: u32,
    pub(crate) kind: TreeEntryKind,
}

#[derive(Clone, Debug)]
pub(crate) enum TreeEntryKind {
    File { digest: Digest, byte_len: u64 },
    Directory { digest: Digest },
    Symlink { digest: Digest },
}

/// Describes why strict decoding or graph validation rejected a canonical
/// object. Callers can distinguish missing objects and size limits from
/// identity and encoding failures without parsing an error message.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CanonicalObjectIssue {
    #[error("{kind} object {digest} is missing")]
    Missing { kind: &'static str, digest: Digest },
    #[error("object is {actual} bytes; limit is {limit}")]
    TooLarge { limit: u64, actual: u64 },
    #[error("object digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch { expected: Digest, actual: Digest },
    #[error("{detail}")]
    InvalidEncoding { detail: String },
}

fn invalid(detail: impl Into<String>) -> CanonicalObjectIssue {
    CanonicalObjectIssue::InvalidEncoding {
        detail: detail.into(),
    }
}

pub(crate) fn decode_file(
    expected: &Digest,
    bytes: &[u8],
) -> Result<Arc<[u8]>, CanonicalObjectIssue> {
    verify_digest(expected, bytes)?;
    let mut reader = Reader::new(bytes);
    reader.domain(FILE_DOMAIN, "file")?;
    reader.version("file")?;
    let length = reader.u64()?;
    if length > MAX_FILE_BYTES {
        return Err(CanonicalObjectIssue::TooLarge {
            limit: MAX_FILE_BYTES,
            actual: length,
        });
    }
    let contents = reader.take(length as usize)?.to_vec();
    reader.end("file")?;
    Ok(Arc::from(contents))
}

pub(crate) fn decode_symlink(
    expected: &Digest,
    bytes: &[u8],
) -> Result<String, CanonicalObjectIssue> {
    verify_digest(expected, bytes)?;
    let mut reader = Reader::new(bytes);
    reader.domain(SYMLINK_DOMAIN, "symlink")?;
    reader.version("symlink")?;
    let target = reader.text(MAX_SYMLINK_BYTES, "symlink target")?;
    let target = std::str::from_utf8(target)
        .map_err(|_| invalid("canonical symlink target is not UTF-8"))?;
    if target.is_empty() || target.chars().any(char::is_control) {
        return Err(invalid(
            "canonical symlink target is empty or contains control characters",
        ));
    }
    reader.end("symlink")?;
    Ok(target.to_owned())
}

pub(crate) fn decode_tree(
    expected: &Digest,
    bytes: &[u8],
) -> Result<TreeObject, CanonicalObjectIssue> {
    verify_digest(expected, bytes)?;
    let mut reader = Reader::new(bytes);
    reader.domain(TREE_DOMAIN, "tree")?;
    reader.version("tree")?;
    let root_mode = reader.u32()?;
    validate_directory_mode(root_mode)?;
    let count = reader.u64()?;
    if count > MAX_ENTRIES as u64 {
        return Err(CanonicalObjectIssue::TooLarge {
            limit: MAX_ENTRIES as u64,
            actual: count,
        });
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut previous: Option<String> = None;
    let mut aggregate = 0_u64;
    let mut file_lengths = BTreeMap::<Digest, u64>::new();
    for _ in 0..count {
        let name = reader.text(255, "tree child name")?;
        let name = std::str::from_utf8(name)
            .map_err(|_| invalid("canonical tree child name is not UTF-8"))?;
        validate_segment(name)?;
        if previous.as_deref().is_some_and(|previous| previous >= name) {
            return Err(invalid(
                "canonical tree entries are not strictly name-sorted",
            ));
        }
        previous = Some(name.to_owned());
        let tag = reader.u8()?;
        let mode = reader.u32()?;
        let digest = reader.digest()?;
        let kind = match tag {
            0 => {
                validate_file_mode(mode)?;
                let byte_len = reader.u64()?;
                if byte_len > MAX_FILE_BYTES {
                    return Err(CanonicalObjectIssue::TooLarge {
                        limit: MAX_FILE_BYTES,
                        actual: byte_len,
                    });
                }
                aggregate = aggregate
                    .checked_add(byte_len)
                    .ok_or_else(|| invalid("canonical tree byte count overflows"))?;
                if aggregate > MAX_FILE_BYTES {
                    return Err(CanonicalObjectIssue::TooLarge {
                        limit: MAX_FILE_BYTES,
                        actual: aggregate,
                    });
                }
                if let Some(first) = file_lengths.insert(digest.clone(), byte_len)
                    && first != byte_len
                {
                    return Err(invalid(
                        "canonical tree assigns conflicting lengths to one file object",
                    ));
                }
                if byte_len == 0 && digest != empty_file_digest() {
                    return Err(invalid(
                        "canonical empty tree file has a noncanonical object identity",
                    ));
                }
                TreeEntryKind::File { digest, byte_len }
            }
            1 => {
                validate_directory_mode(mode)?;
                TreeEntryKind::Directory { digest }
            }
            2 if mode == 0o777 => TreeEntryKind::Symlink { digest },
            2 => {
                return Err(invalid("canonical tree symlink mode is not normalized"));
            }
            _ => {
                return Err(invalid("canonical tree has an unknown entry tag"));
            }
        };
        entries.push(TreeEntry {
            name: name.to_owned(),
            mode,
            kind,
        });
    }
    reader.end("tree")?;
    Ok(TreeObject { root_mode, entries })
}

fn validate_graph(root: &Digest, objects: &CanonicalObjects) -> Result<(), CanonicalObjectIssue> {
    if !objects.trees.contains_key(root) {
        return Err(CanonicalObjectIssue::Missing {
            kind: "tree",
            digest: root.clone(),
        });
    }
    let mut state = WalkState::default();
    let mut ancestors = BTreeSet::new();
    walk_tree(root, "", 0, objects, &mut ancestors, &mut state)?;
    validate_symlink_graph(&state.links, &objects.symlinks)
}

#[derive(Default)]
struct WalkState {
    entries: usize,
    file_bytes: u64,
    file_lengths: BTreeMap<Digest, u64>,
    links: BTreeMap<String, Digest>,
}

fn walk_tree(
    digest: &Digest,
    prefix: &str,
    depth: usize,
    objects: &CanonicalObjects,
    ancestors: &mut BTreeSet<Digest>,
    state: &mut WalkState,
) -> Result<(), CanonicalObjectIssue> {
    if !ancestors.insert(digest.clone()) {
        return Err(invalid("canonical tree contains a directory cycle"));
    }
    let tree = objects
        .trees
        .get(digest)
        .ok_or_else(|| CanonicalObjectIssue::Missing {
            kind: "tree",
            digest: digest.clone(),
        })?;
    for entry in &tree.entries {
        let path = join_path(prefix, &entry.name);
        let entry_depth = depth + 1;
        if entry_depth > MAX_DEPTH || path.len() > MAX_PATH_BYTES {
            return Err(invalid(
                "canonical tree exceeds its depth or path-byte limit",
            ));
        }
        state.entries += 1;
        if state.entries > MAX_ENTRIES {
            return Err(invalid("canonical tree graph exceeds its entry limit"));
        }
        match &entry.kind {
            TreeEntryKind::File { digest, byte_len } => {
                let bytes =
                    objects
                        .files
                        .get(digest)
                        .ok_or_else(|| CanonicalObjectIssue::Missing {
                            kind: "file",
                            digest: digest.clone(),
                        })?;
                if bytes.len() as u64 != *byte_len {
                    return Err(invalid(format!(
                        "tree path {path:?} has inconsistent file length"
                    )));
                }
                state.file_bytes = state
                    .file_bytes
                    .checked_add(*byte_len)
                    .ok_or_else(|| invalid("canonical tree graph byte count overflows"))?;
                if state.file_bytes > MAX_FILE_BYTES {
                    return Err(CanonicalObjectIssue::TooLarge {
                        limit: MAX_FILE_BYTES,
                        actual: state.file_bytes,
                    });
                }
                if let Some(first) = state.file_lengths.insert(digest.clone(), *byte_len)
                    && first != *byte_len
                {
                    return Err(invalid(
                        "canonical tree graph assigns conflicting file lengths",
                    ));
                }
            }
            TreeEntryKind::Directory { digest: child } => {
                let child_tree =
                    objects
                        .trees
                        .get(child)
                        .ok_or_else(|| CanonicalObjectIssue::Missing {
                            kind: "tree",
                            digest: child.clone(),
                        })?;
                if child_tree.root_mode != entry.mode {
                    return Err(invalid(format!(
                        "tree path {path:?} has inconsistent directory mode"
                    )));
                }
                walk_tree(child, &path, entry_depth, objects, ancestors, state)?;
            }
            TreeEntryKind::Symlink { digest } => {
                if !objects.symlinks.contains_key(digest) {
                    return Err(CanonicalObjectIssue::Missing {
                        kind: "symlink",
                        digest: digest.clone(),
                    });
                }
                state.links.insert(path, digest.clone());
            }
        }
    }
    ancestors.remove(digest);
    Ok(())
}

fn validate_symlink_graph(
    links: &BTreeMap<String, Digest>,
    objects: &BTreeMap<Digest, String>,
) -> Result<(), CanonicalObjectIssue> {
    let mut targets = BTreeMap::new();
    for (path, digest) in links {
        let target = objects
            .get(digest)
            .ok_or_else(|| CanonicalObjectIssue::Missing {
                kind: "symlink",
                digest: digest.clone(),
            })?;
        targets.insert(path.clone(), safe_target_path(path, target)?);
    }
    let mut edges = BTreeMap::<String, Vec<String>>::new();
    let mut incoming = links
        .keys()
        .map(|path| (path.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for (path, target) in &targets {
        let mut prefix = String::new();
        for segment in target.split('/') {
            prefix = join_path(&prefix, segment);
            if links.contains_key(&prefix) {
                edges.entry(path.clone()).or_default().push(prefix.clone());
                *incoming
                    .get_mut(&prefix)
                    .expect("known symlink dependency has an incoming counter") += 1;
            }
        }
    }
    let mut ready = incoming
        .iter()
        .filter_map(|(path, count)| (*count == 0).then_some(path.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0;
    while let Some(path) = ready.pop_front() {
        visited += 1;
        for dependency in edges.get(&path).into_iter().flatten() {
            let count = incoming
                .get_mut(dependency)
                .expect("known symlink dependency has an incoming counter");
            *count -= 1;
            if *count == 0 {
                ready.push_back(dependency.clone());
            }
        }
    }
    if visited != incoming.len() {
        return Err(invalid("canonical tree contains a symbolic-link cycle"));
    }
    Ok(())
}

fn safe_target_path(path: &str, target: &str) -> Result<String, CanonicalObjectIssue> {
    if target.starts_with('/') || target.contains('\\') {
        return Err(invalid("canonical symlink target is not safe-relative"));
    }
    for segment in target.split('/') {
        validate_segment(segment)?;
    }
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    let resolved = join_path(parent, target);
    if resolved.split('/').count() > MAX_DEPTH || resolved.len() > MAX_PATH_BYTES {
        return Err(invalid("canonical symlink target exceeds tree path bounds"));
    }
    Ok(resolved)
}

fn validate_segment(value: &str) -> Result<(), CanonicalObjectIssue> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(invalid("invalid canonical tree path segment"));
    }
    Ok(())
}

fn validate_file_mode(mode: u32) -> Result<(), CanonicalObjectIssue> {
    if mode & !0o777 != 0 || mode & 0o400 == 0 {
        return Err(invalid("invalid canonical tree file mode"));
    }
    Ok(())
}

fn validate_directory_mode(mode: u32) -> Result<(), CanonicalObjectIssue> {
    if mode & !0o777 != 0 || mode & 0o500 != 0o500 {
        return Err(invalid("invalid canonical tree directory mode"));
    }
    Ok(())
}

fn empty_file_digest() -> Digest {
    let mut bytes = FILE_DOMAIN.to_vec();
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    Digest::sha256(bytes)
}

fn verify_digest(expected: &Digest, bytes: &[u8]) -> Result<(), CanonicalObjectIssue> {
    let actual = Digest::sha256(bytes);
    if &actual != expected {
        return Err(CanonicalObjectIssue::DigestMismatch {
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

fn join_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn domain(&mut self, expected: &[u8], kind: &str) -> Result<(), CanonicalObjectIssue> {
        if self.take(expected.len())? != expected {
            return Err(invalid(format!(
                "canonical {kind} object has the wrong domain"
            )));
        }
        Ok(())
    }

    fn version(&mut self, kind: &str) -> Result<(), CanonicalObjectIssue> {
        let found = self.u16()?;
        if found != VERSION {
            return Err(invalid(format!(
                "unsupported canonical {kind} object version {found}"
            )));
        }
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CanonicalObjectIssue> {
        if self.remaining.len() < length {
            return Err(invalid("truncated canonical object"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CanonicalObjectIssue> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CanonicalObjectIssue> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("exact u16 width"),
        ))
    }

    fn u32(&mut self) -> Result<u32, CanonicalObjectIssue> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("exact u32 width"),
        ))
    }

    fn u64(&mut self) -> Result<u64, CanonicalObjectIssue> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("exact u64 width"),
        ))
    }

    fn text(&mut self, maximum: usize, role: &str) -> Result<&'a [u8], CanonicalObjectIssue> {
        let length = self.u64()?;
        if length > maximum as u64 {
            return Err(invalid(format!("canonical {role} exceeds its byte limit")));
        }
        self.take(length as usize)
    }

    fn digest(&mut self) -> Result<Digest, CanonicalObjectIssue> {
        let bytes = self.text(71, "digest")?;
        if bytes.len() != 71 {
            return Err(invalid("canonical object digest has the wrong length"));
        }
        let value = std::str::from_utf8(bytes)
            .map_err(|_| invalid("canonical object digest is not UTF-8"))?;
        Digest::new(value).map_err(|error| invalid(error.to_string()))
    }

    fn end(&self, kind: &str) -> Result<(), CanonicalObjectIssue> {
        if !self.remaining.is_empty() {
            return Err(invalid(format!(
                "canonical {kind} object has trailing bytes"
            )));
        }
        Ok(())
    }
}
