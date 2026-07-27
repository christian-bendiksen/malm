//! Crash and pause injection for debug-only tests.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_PAUSE_TIMEOUT_MS: u64 = 30_000;
const PAUSE_POLL_INTERVAL: Duration = Duration::from_millis(5);

pub(crate) fn hit(name: &str) {
    static HITS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();

    let Ok(spec) = std::env::var("MALM_FAILPOINT") else {
        return;
    };
    for entry in spec.split(',') {
        let entry = entry.trim();
        let (point, nth) = match entry.split_once('=') {
            Some((point, nth)) => (point, nth.parse().unwrap_or(1)),
            None => (entry, 1),
        };
        if point != name {
            continue;
        }
        let mut hits = HITS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = hits.entry(name.to_owned()).or_insert(0);
        *count += 1;
        if *count == nth {
            drop(hits);
            if std::env::var("MALM_FAILPOINT_MODE").as_deref() == Ok("pause") {
                pause(name, nth);
            } else {
                eprintln!("failpoint {name}: aborting (hit {nth})");
                std::process::abort();
            }
        }
    }
}

fn pause(name: &str, nth: u64) {
    let marker = required_path(name, "MALM_FAILPOINT_MARKER");
    let continue_path = required_path(name, "MALM_FAILPOINT_CONTINUE");
    let timeout = pause_timeout(name);
    let mut marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .unwrap_or_else(|error| abort_pause(name, &format!("cannot create marker: {error}")));
    marker_file
        .write_all(format!("{name}={nth}\n").as_bytes())
        .unwrap_or_else(|error| abort_pause(name, &format!("cannot write marker: {error}")));
    marker_file
        .sync_all()
        .unwrap_or_else(|error| abort_pause(name, &format!("cannot sync marker: {error}")));

    eprintln!("failpoint {name}: paused (hit {nth})");
    let started = Instant::now();
    loop {
        match continue_path.try_exists() {
            Ok(true) => {
                std::fs::remove_file(&continue_path).unwrap_or_else(|error| {
                    abort_pause(name, &format!("cannot consume continue file: {error}"))
                });
                eprintln!("failpoint {name}: continuing (hit {nth})");
                return;
            }
            Ok(false) => {}
            Err(error) => abort_pause(name, &format!("cannot inspect continue file: {error}")),
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            abort_pause(name, "timed out waiting for continue file");
        }
        std::thread::sleep(PAUSE_POLL_INTERVAL.min(timeout.saturating_sub(elapsed)));
    }
}

fn required_path(name: &str, variable: &str) -> PathBuf {
    let Some(value) = std::env::var_os(variable) else {
        abort_pause(name, &format!("{variable} is not set"));
    };
    if value.is_empty() {
        abort_pause(name, &format!("{variable} is empty"));
    }
    PathBuf::from(value)
}

fn pause_timeout(name: &str) -> Duration {
    let milliseconds = match std::env::var("MALM_FAILPOINT_TIMEOUT_MS") {
        Ok(value) => value.parse::<u64>().unwrap_or_else(|error| {
            abort_pause(
                name,
                &format!("MALM_FAILPOINT_TIMEOUT_MS is invalid: {error}"),
            )
        }),
        Err(std::env::VarError::NotPresent) => DEFAULT_PAUSE_TIMEOUT_MS,
        Err(std::env::VarError::NotUnicode(_)) => {
            abort_pause(name, "MALM_FAILPOINT_TIMEOUT_MS is not UTF-8")
        }
    };
    Duration::from_millis(milliseconds)
}

fn abort_pause(name: &str, reason: &str) -> ! {
    eprintln!("failpoint {name}: pause failed: {reason}");
    std::process::abort();
}
