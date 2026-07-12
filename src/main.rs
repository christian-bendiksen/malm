//! CLI process entry point and exit-code contract.
//!
//! # Exit-code contract
//!
//! - `0` means success.
//! - `1` means the command ran successfully but reports a non-error condition:
//!   drift (`status`), blocked findings (`plan`), findings (`state fsck`),
//!   or an incomplete recovery (`state recover`). Monitoring that treats a
//!   non-zero exit as "needs attention" should use `!= 0`.
//! - `2` means a tool/config error prevented the command from running (unreadable state,
//!   IO failure, parse error, policy refusal). This is distinct from `1` so
//!   a wrapper can tell "host drifted" apart from "malm itself failed".
fn main() {
    match malm::api::run_cli() {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    }
}
