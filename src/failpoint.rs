//! Crash injection for integration tests.
//!
//! Without the `failpoints` feature, `failpoint!` expands to nothing. Release
//! builds reject that feature.
//!
//! When enabled, each site reads `MALM_FAILPOINT`, a comma-separated list of
//! names optionally suffixed with `=N` to abort on the Nth hit. Aborting skips
//! destructors and buffered writes to approximate a hard crash.

#[cfg(feature = "failpoints")]
pub fn hit(name: &str) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
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
            eprintln!("failpoint {name}: aborting (hit {nth})");
            std::process::abort();
        }
    }
}

#[macro_export]
macro_rules! failpoint {
    ($name:expr) => {
        #[cfg(feature = "failpoints")]
        $crate::failpoint::hit($name);
    };
}
