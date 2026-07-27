//! Validates the frozen canonical pack-object encoding offline.

use malm_types::Digest;

const DOMAIN: &[u8] = b"malm-pack-content\0";
const ENCODING_VERSION: u16 = 1;
const MAX_PACK_TREE_ENTRIES: u64 = 100_000;
const MAX_PACK_TREE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PACK_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PACK_PATH_BYTES: usize = 1024;
const MAX_PACK_PATH_SEGMENTS: usize = 32;
const MAX_PATH_SEGMENT_BYTES: usize = 255;
pub(crate) const MAX_PACK_OBJECT_BYTES: u64 =
    MAX_PACK_TREE_BYTES + MAX_PACK_TREE_ENTRIES * (16 + MAX_PACK_PATH_BYTES as u64) + 64;

pub(crate) fn validate(bytes: &[u8], expected: &Digest) -> bool {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PACK_OBJECT_BYTES
        || Digest::sha256(bytes) != *expected
    {
        return false;
    }
    let mut reader = Reader::new(bytes);
    if reader.read(DOMAIN.len()) != Some(DOMAIN) || reader.u16() != Some(ENCODING_VERSION) {
        return false;
    }
    let Some(count) = reader.u64() else {
        return false;
    };
    if count > MAX_PACK_TREE_ENTRIES {
        return false;
    }

    let mut previous = Vec::new();
    let mut total_bytes = 0_u64;
    let mut found_manifest = false;
    for _ in 0..count {
        let Some(path_len) = reader.u64().and_then(|length| usize::try_from(length).ok()) else {
            return false;
        };
        if path_len == 0 || path_len > MAX_PACK_PATH_BYTES {
            return false;
        }
        let Some(path) = reader.read(path_len) else {
            return false;
        };
        if !previous.is_empty() && previous.as_slice() >= path {
            return false;
        }
        if !valid_path(path) {
            return false;
        }
        found_manifest |= path == b"malm-pack.kdl";
        previous.clear();
        previous.extend_from_slice(path);

        let Some(file_len) = reader.u64() else {
            return false;
        };
        total_bytes = match total_bytes.checked_add(file_len) {
            Some(total) if total <= MAX_PACK_TREE_BYTES => total,
            _ => return false,
        };
        let Some(file_len) = usize::try_from(file_len).ok() else {
            return false;
        };
        if file_len as u64 > MAX_PACK_FILE_BYTES || reader.read(file_len).is_none() {
            return false;
        }
    }
    found_manifest && reader.is_finished()
}

fn valid_path(bytes: &[u8]) -> bool {
    let Ok(path) = std::str::from_utf8(bytes) else {
        return false;
    };
    if path.starts_with('/') || path.contains('\\') || path.chars().any(char::is_control) {
        return false;
    }
    let mut count = 0_usize;
    for segment in path.split('/') {
        count += 1;
        if segment.is_empty()
            || matches!(
                segment,
                "." | ".." | ".git" | "malm.lock" | ".malm-lock.tmp"
            )
            || segment.len() > MAX_PATH_SEGMENT_BYTES
        {
            return false;
        }
    }
    count <= MAX_PACK_PATH_SEGMENTS
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let value = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.read(2)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.read(8)?.try_into().ok()?))
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(path: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&ENCODING_VERSION.to_be_bytes());
        bytes.extend_from_slice(&1_u64.to_be_bytes());
        bytes.extend_from_slice(&(path.len() as u64).to_be_bytes());
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn validates_the_frozen_pack_object_envelope() {
        let bytes = object(b"malm-pack.kdl", b"pack \"example\"\n");
        assert!(validate(&bytes, &Digest::sha256(&bytes)));

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(!validate(&trailing, &Digest::sha256(&trailing)));
        let reserved = object(b"nested/malm.lock", b"reserved");
        assert!(!validate(&reserved, &Digest::sha256(&reserved)));
        assert!(!validate(&bytes, &Digest::sha256(b"another object")));
    }
}
