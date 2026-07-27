use std::io;
use std::thread;
use std::time::Duration;

use wasmtime::Engine;

#[derive(Clone, Copy, Debug)]
pub(crate) struct WatchdogConfig {
    pub(crate) tick_interval: Duration,
    pub(crate) deadline_ticks: u64,
}

impl WatchdogConfig {
    pub(crate) const PRODUCTION: Self = Self {
        tick_interval: Duration::from_millis(100),
        deadline_ticks: 300,
    };
}

pub(crate) fn start(engine: &Engine, tick_interval: Duration) -> io::Result<()> {
    let engine = engine.weak();
    thread::Builder::new()
        .name("malm-format-component-epoch".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(tick_interval);
                let Some(engine) = engine.upgrade() else {
                    break;
                };
                engine.increment_epoch();
            }
        })
        .map(|_| ())
}
