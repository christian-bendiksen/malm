//! flock-based advisory locking with a "waiting for another malm
//! process" notice on contention.

use anyhow::{Context, Result};
use rustix::fs::FlockOperation;
use std::fs::File;

pub fn lock_exclusive_with_feedback(file: &File, label: &str) -> Result<()> {
    match rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => return Ok(()),
        Err(rustix::io::Errno::WOULDBLOCK) => {
            eprintln!("  waiting for another malm process to release the {label}…");
        }
        Err(errno) => return Err(errno).with_context(|| format!("lock {label}")),
    }
    loop {
        match rustix::fs::flock(file, FlockOperation::LockExclusive) {
            Ok(()) => return Ok(()),
            // A signal during the blocking wait is not a failure; retry.
            Err(rustix::io::Errno::INTR) => {}
            Err(errno) => return Err(errno).with_context(|| format!("lock {label}")),
        }
    }
}

pub fn lock_shared_with_feedback(file: &File, label: &str) -> Result<()> {
    match rustix::fs::flock(file, FlockOperation::NonBlockingLockShared) {
        Ok(()) => return Ok(()),
        Err(rustix::io::Errno::WOULDBLOCK) => {
            eprintln!("  waiting for another malm process to release the {label}…");
        }
        Err(errno) => return Err(errno).with_context(|| format!("lock {label}")),
    }
    loop {
        match rustix::fs::flock(file, FlockOperation::LockShared) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::INTR) => {}
            Err(errno) => return Err(errno).with_context(|| format!("lock {label}")),
        }
    }
}

pub fn unlock(file: &File) {
    let _ = rustix::fs::flock(file, FlockOperation::Unlock);
}
