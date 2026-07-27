#![forbid(unsafe_code)]
//! Entry point for the Malm executable.
//!
//! Exit status 0 means success, 1 means a successful inspection found drift or
//! other findings, and 2 means a request, authority, store, or execution error.

fn main() {
    match malm::api::run_cli() {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(2);
        }
    }
}
