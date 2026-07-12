//! Transaction ids and display aliases.

use crate::domain::id::TransactionId;

const TRANSACTION_ALIAS_LEN: usize = 12;

// The zero-padded seconds/nanoseconds prefix makes lexicographic ID order
// chronological. GC uses this to break completion-time ties.
pub fn new_transaction_id() -> TransactionId {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let raw = format!(
        "{:010}-{:09}-{}-{:016x}",
        duration.as_secs(),
        duration.subsec_nanos(),
        std::process::id(),
        random_u64()
    );
    // This format always matches [A-Za-z0-9_-]+. Keep validation in `new` as
    // an invariant check.
    TransactionId::new(raw).expect("generated transaction id is always valid")
}

pub fn transaction_alias(id: &str) -> String {
    let Some(random_suffix) = id.rsplit('-').next() else {
        return id.chars().take(TRANSACTION_ALIAS_LEN).collect();
    };
    if random_suffix.len() == 16 && random_suffix.chars().all(|c| c.is_ascii_hexdigit()) {
        random_suffix.chars().take(TRANSACTION_ALIAS_LEN).collect()
    } else {
        id.chars().take(TRANSACTION_ALIAS_LEN).collect()
    }
}

// ID generation must not abort an apply, so use hasher entropy if getrandom
// fails.
fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_ok() {
        return u64::from_le_bytes(buf);
    }
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}
